"""
Management command for deal workflow maintenance and automation
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Count, Q
from apps.deals.models import Deal, Payment
from deals.workflow_automation import DealWorkflowEngine, DealPerformanceAnalyzer
from apps.organization.models import Organization
from datetime import timedelta


class Command(BaseCommand):
    help = 'Perform deal workflow maintenance and automation tasks'

    def add_arguments(self, parser):
        parser.add_argument(
            '--organization',
            type=str,
            help='Specific organization name to process'
        )
        parser.add_argument(
            '--fix-payment-status',
            action='store_true',
            help='Automatically fix inconsistent payment statuses'
        )
        parser.add_argument(
            '--identify-bottlenecks',
            action='store_true',
            help='Identify and report workflow bottlenecks'
        )
        parser.add_argument(
            '--performance-analysis',
            action='store_true',
            help='Run comprehensive performance analysis'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output'
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting deal workflow maintenance...')
        )

        organization = None
        if options['organization']:
            try:
                organization = Organization.objects.get(name=options['organization'])
                self.stdout.write(f"Processing organization: {organization.name}")
            except Organization.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f"Organization '{options['organization']}' not found")
                )
                return

        if options['fix_payment_status']:
            self.fix_payment_statuses(organization, options['dry_run'], options['verbose'])
        
        if options['identify_bottlenecks']:
            self.identify_bottlenecks(organization, options['verbose'])
        
        if options['performance_analysis']:
            self.run_performance_analysis(organization, options['verbose'])
        
        # Always run basic maintenance
        self.run_basic_maintenance(organization, options['verbose'])

    def fix_payment_statuses(self, organization, dry_run, verbose):
        """Fix inconsistent payment statuses"""
        self.stdout.write("\n=== Fixing Payment Status Inconsistencies ===")
        
        # Get deals with potential payment status issues
        deals_query = Deal.objects.all()
        if organization:
            deals_query = deals_query.filter(organization=organization)
        
        fixed_count = 0
        issues_found = 0
        
        for deal in deals_query:
            suggestion = DealWorkflowEngine.auto_update_payment_status(deal)
            
            if suggestion['requires_update']:
                issues_found += 1
                
                if verbose:
                    self.stdout.write(
                        f"  Deal {deal.deal_id}: {deal.payment_status} -> {suggestion['suggested_status']} "
                        f"(Paid: {suggestion['total_paid']}, Value: {suggestion['deal_value']})"
                    )
                
                if not dry_run:
                    try:
                        DealWorkflowEngine.execute_status_transition(
                            deal=deal,
                            new_payment_status=suggestion['suggested_status'],
                            remarks="Auto-corrected payment status based on payment records"
                        )
                        fixed_count += 1
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(f"  Failed to fix {deal.deal_id}: {str(e)}")
                        )
        
        self.stdout.write(f"Payment Status Issues Found: {issues_found}")
        if not dry_run:
            self.stdout.write(f"Payment Status Issues Fixed: {fixed_count}")
        else:
            self.stdout.write("(Dry run - no changes made)")

    def identify_bottlenecks(self, organization, verbose):
        """Identify workflow bottlenecks"""
        self.stdout.write("\n=== Identifying Workflow Bottlenecks ===")
        
        bottlenecks = DealPerformanceAnalyzer.get_workflow_bottlenecks(organization)
        
        if bottlenecks['total_issues'] == 0:
            self.stdout.write(self.style.SUCCESS("No significant bottlenecks identified"))
            return
        
        self.stdout.write(f"Total Issues Found: {bottlenecks['total_issues']}")
        self.stdout.write(f"High Severity Issues: {bottlenecks['high_severity_count']}")
        
        for bottleneck in bottlenecks['bottlenecks']:
            severity_style = self.style.ERROR if bottleneck['severity'] == 'high' else self.style.WARNING
            
            self.stdout.write(
                severity_style(f"\n{bottleneck['type'].upper()} ({bottleneck['severity']} severity)")
            )
            self.stdout.write(f"  Issue: {bottleneck['description']}")
            self.stdout.write(f"  Recommendation: {bottleneck['recommendation']}")
            
            if verbose and 'count' in bottleneck:
                self.stdout.write(f"  Affected Items: {bottleneck['count']}")

    def run_performance_analysis(self, organization, verbose):
        """Run comprehensive performance analysis"""
        self.stdout.write("\n=== Performance Analysis ===")
        
        # Verification performance
        verification_perf = DealPerformanceAnalyzer.analyze_verification_performance(
            organization=organization, days=30
        )
        
        self.stdout.write("\nVerification Performance (Last 30 Days):")
        self.stdout.write(f"  Total Deals: {verification_perf['total_deals']}")
        self.stdout.write(f"  Verification Rate: {verification_perf['verification_rate']:.1f}%")
        self.stdout.write(f"  Rejection Rate: {verification_perf['rejection_rate']:.1f}%")
        self.stdout.write(f"  Avg Verification Time: {verification_perf['avg_verification_time_hours']:.1f} hours")
        
        if verification_perf['verification_rate'] < 80:
            self.stdout.write(
                self.style.WARNING("  ⚠️  Low verification rate - consider process improvements")
            )
        
        if verification_perf['avg_verification_time_hours'] > 48:
            self.stdout.write(
                self.style.WARNING("  ⚠️  Slow verification process - consider automation")
            )
        
        # Payment performance
        payment_perf = DealPerformanceAnalyzer.analyze_payment_workflow_performance(
            organization=organization, days=30
        )
        
        self.stdout.write("\nPayment Performance (Last 30 Days):")
        self.stdout.write(f"  Total Deals: {payment_perf['total_deals']}")
        self.stdout.write(f"  Payment Completion Rate: {payment_perf['payment_completion_rate']:.1f}%")
        self.stdout.write(f"  Avg Payment Completion: {payment_perf['avg_payment_completion_days']:.1f} days")
        
        if payment_perf['payment_completion_rate'] < 70:
            self.stdout.write(
                self.style.WARNING("  ⚠️  Low payment completion rate - implement follow-up processes")
            )
        
        if verbose:
            self.stdout.write("\nPayment Method Performance:")
            for method in payment_perf['payment_method_performance']:
                self.stdout.write(
                    f"  {method['payment_method']}: {method['count']} deals, "
                    f"{method['avg_completion_rate']*100:.1f}% completion rate"
                )

    def run_basic_maintenance(self, organization, verbose):
        """Run basic maintenance tasks"""
        self.stdout.write("\n=== Basic Maintenance ===")
        
        # Get pending workflow actions
        pending_actions = DealWorkflowEngine.get_pending_workflow_actions(
            organization=organization
        )
        
        self.stdout.write(f"Total Actions Required: {pending_actions['total_actions_required']}")
        
        if pending_actions['verification_pending']:
            self.stdout.write(
                f"  Verification Pending: {len(pending_actions['verification_pending'])} deals"
            )
            
            if verbose:
                for deal in pending_actions['verification_pending'][:5]:  # Show first 5
                    days_pending = (timezone.now() - deal.created_at).days
                    self.stdout.write(f"    {deal.deal_id}: {days_pending} days pending")
        
        if pending_actions['payment_without_verification']:
            self.stdout.write(
                f"  Payment Without Verification: {len(pending_actions['payment_without_verification'])} deals"
            )
        
        if pending_actions['approaching_due']:
            self.stdout.write(
                f"  Approaching Due Date: {len(pending_actions['approaching_due'])} deals"
            )
            
            if verbose:
                for deal in pending_actions['approaching_due'][:5]:  # Show first 5
                    days_until_due = (deal.due_date - timezone.now().date()).days
                    self.stdout.write(f"    {deal.deal_id}: {days_until_due} days until due")
        
        if pending_actions['inconsistent_payment']:
            self.stdout.write(
                f"  Inconsistent Payment Status: {len(pending_actions['inconsistent_payment'])} deals"
            )
        
        # Recommendations
        self.stdout.write("\n=== Recommendations ===")
        
        recommendations = []
        
        if len(pending_actions['verification_pending']) > 10:
            recommendations.append("• Assign additional verification resources")
            recommendations.append("• Implement automated verification rules for standard deals")
        
        if len(pending_actions['approaching_due']) > 5:
            recommendations.append("• Implement automated payment reminders")
            recommendations.append("• Set up due date alerts for deal creators")
        
        if len(pending_actions['inconsistent_payment']) > 0:
            recommendations.append("• Run payment status fix with --fix-payment-status")
        
        if pending_actions['total_actions_required'] > 20:
            recommendations.append("• Consider workflow automation improvements")
            recommendations.append("• Review deal processing procedures")
        
        if not recommendations:
            recommendations.append("• Workflow is running smoothly")
        
        for rec in recommendations:
            self.stdout.write(rec)
        
        self.stdout.write(f"\nMaintenance completed at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")