"""
Management command to optimize business logic workflows
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.db import transaction
from datetime import timedelta
import logging

from deals.enhanced_workflow_optimizer import EnhancedDealWorkflowOptimizer
from authentication.user_org_optimizer import UserOrganizationOptimizer
from apps.organization.models import Organization

class Command(BaseCommand):
    help = 'Optimize business logic workflows including deal workflows and user management'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--organization',
            type=str,
            help='Organization name to optimize (if not provided, optimizes all organizations)'
        )
        
        parser.add_argument(
            '--workflow-type',
            type=str,
            choices=['deals', 'users', 'all'],
            default='all',
            help='Type of workflow to optimize'
        )
        
        parser.add_argument(
            '--batch-size',
            type=int,
            default=100,
            help='Batch size for processing deals'
        )
        
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to analyze for metrics'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be optimized without making changes'
        )
        
        parser.add_argument(
            '--generate-report',
            action='store_true',
            help='Generate comprehensive optimization report'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
    
    def handle(self, *args, **options):
        self.verbosity = options.get('verbosity', 1)
        self.verbose = options.get('verbose', False)
        
        # Get organization if specified
        organization = None
        if options['organization']:
            try:
                organization = Organization.objects.get(name=options['organization'])
                self.stdout.write(f"Optimizing workflows for organization: {organization.name}")
            except Organization.DoesNotExist:
                raise CommandError(f"Organization '{options['organization']}' not found")
        else:
            self.stdout.write("Optimizing workflows for all organizations")
        
        workflow_type = options['workflow_type']
        batch_size = options['batch_size']
        days = options['days']
        dry_run = options['dry_run']
        generate_report = options['generate_report']
        
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
        
        try:
            # Optimize deal workflows
            if workflow_type in ['deals', 'all']:
                self.stdout.write("\n" + "="*50)
                self.stdout.write("OPTIMIZING DEAL WORKFLOWS")
                self.stdout.write("="*50)
                
                if not dry_run:
                    deal_results = self._optimize_deal_workflows(organization, batch_size)
                    self._display_deal_optimization_results(deal_results)
                else:
                    self._preview_deal_optimization(organization)
                
                # Get deal workflow metrics
                self.stdout.write("\nGetting deal workflow metrics...")
                deal_metrics = EnhancedDealWorkflowOptimizer.get_workflow_performance_metrics(
                    organization=organization,
                    days=days
                )
                self._display_deal_metrics(deal_metrics)
            
            # Optimize user management workflows
            if workflow_type in ['users', 'all']:
                self.stdout.write("\n" + "="*50)
                self.stdout.write("OPTIMIZING USER MANAGEMENT WORKFLOWS")
                self.stdout.write("="*50)
                
                if not dry_run:
                    user_results = self._optimize_user_workflows(organization)
                    self._display_user_optimization_results(user_results)
                else:
                    self._preview_user_optimization(organization)
                
                # Get user activity analytics (only for specific organization)
                if organization:
                    self.stdout.write("\nGetting user activity analytics...")
                    user_analytics = UserOrganizationOptimizer.add_user_activity_tracking(
                        organization=organization,
                        days=days
                    )
                    self._display_user_analytics(user_analytics)
            
            # Generate comprehensive report
            if generate_report:
                self.stdout.write("\n" + "="*50)
                self.stdout.write("GENERATING OPTIMIZATION REPORT")
                self.stdout.write("="*50)
                self._generate_comprehensive_report(organization, days)
            
            self.stdout.write(
                self.style.SUCCESS(f"\nBusiness logic optimization completed successfully!")
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Optimization failed: {str(e)}")
            )
            if self.verbose:
                import traceback
                self.stdout.write(traceback.format_exc())
            raise CommandError(f"Optimization failed: {str(e)}")
    
    def _optimize_deal_workflows(self, organization, batch_size):
        """Optimize deal workflows"""
        self.stdout.write(f"Optimizing deal state transitions (batch size: {batch_size})...")
        
        result = EnhancedDealWorkflowOptimizer.optimize_deal_state_transitions(
            organization=organization,
            batch_size=batch_size
        )
        
        return result
    
    def _preview_deal_optimization(self, organization):
        """Preview what would be optimized in deal workflows"""
        self.stdout.write("Analyzing deals that would be optimized...")
        
        # This would show what deals have inconsistent states without fixing them
        from apps.deals.models import Deal
        
        base_query = Deal.objects.select_related('client', 'organization')
        if organization:
            base_query = base_query.filter(organization=organization)
        
        # Count deals with potential issues
        inconsistent_payment_status = 0
        long_pending_verification = 0
        
        for deal in base_query.prefetch_related('payments'):
            total_paid = deal.get_total_paid_amount()
            deal_value = float(deal.deal_value)
            
            # Check payment status consistency
            if total_paid == 0:
                correct_status = 'initial payment'
            elif abs(total_paid - deal_value) <= 0.01:
                correct_status = 'full_payment'
            else:
                correct_status = 'partial_payment'
            
            if deal.payment_status != correct_status:
                inconsistent_payment_status += 1
            
            # Check verification delays
            if (deal.verification_status == 'pending' and 
                deal.created_at < timezone.now() - timedelta(days=7)):
                long_pending_verification += 1
        
        self.stdout.write(f"  - Deals with inconsistent payment status: {inconsistent_payment_status}")
        self.stdout.write(f"  - Deals with long pending verification: {long_pending_verification}")
        self.stdout.write(f"  - Total deals that would be optimized: {inconsistent_payment_status + long_pending_verification}")
    
    def _optimize_user_workflows(self, organization):
        """Optimize user management workflows"""
        self.stdout.write("Optimizing organization and user management workflows...")
        
        result = UserOrganizationOptimizer.optimize_organization_creation_workflow(
            organization=organization
        )
        
        return result
    
    def _preview_user_optimization(self, organization):
        """Preview what would be optimized in user workflows"""
        self.stdout.write("Analyzing user management optimizations...")
        
        if organization:
            organizations = [organization]
        else:
            organizations = Organization.objects.filter(is_active=True)
        
        total_users = 0
        total_roles = 0
        
        for org in organizations:
            users_count = org.users.filter(is_active=True).count()
            roles_count = org.roles.count()
            
            total_users += users_count
            total_roles += roles_count
            
            if self.verbose:
                self.stdout.write(f"  - {org.name}: {users_count} users, {roles_count} roles")
        
        self.stdout.write(f"  - Total active users: {total_users}")
        self.stdout.write(f"  - Total roles: {total_roles}")
        self.stdout.write(f"  - Organizations to optimize: {len(organizations)}")
    
    def _display_deal_optimization_results(self, results):
        """Display deal optimization results"""
        self.stdout.write(f"\nDeal Workflow Optimization Results:")
        self.stdout.write(f"  - Processed deals: {results['processed_deals']}")
        self.stdout.write(f"  - Optimized transitions: {results['optimized_transitions']}")
        self.stdout.write(f"  - Validation errors: {len(results['validation_errors'])}")
        
        if results['validation_errors'] and self.verbose:
            self.stdout.write("  Validation errors:")
            for error in results['validation_errors'][:5]:  # Show first 5 errors
                self.stdout.write(f"    - {error}")
        
        if results['recommendations']:
            self.stdout.write("  Recommendations:")
            for rec in results['recommendations']:
                self.stdout.write(f"    - [{rec['priority'].upper()}] {rec['description']}")
                if self.verbose:
                    self.stdout.write(f"      Action: {rec['action']}")
    
    def _display_user_optimization_results(self, results):
        """Display user optimization results"""
        self.stdout.write(f"\nUser Management Optimization Results:")
        self.stdout.write(f"  - Processed organizations: {results['processed_organizations']}")
        self.stdout.write(f"  - Optimized role assignments: {results['optimized_role_assignments']}")
        self.stdout.write(f"  - Bulk operations created: {results['bulk_operations_created']}")
        
        if results['recommendations']:
            self.stdout.write("  Recommendations:")
            for rec in results['recommendations']:
                self.stdout.write(f"    - [{rec['priority'].upper()}] {rec['description']}")
                if self.verbose:
                    self.stdout.write(f"      Action: {rec['action']}")
    
    def _display_deal_metrics(self, metrics):
        """Display deal workflow metrics"""
        self.stdout.write(f"\nDeal Workflow Metrics:")
        self.stdout.write(f"  - Total deals: {metrics['total_deals']}")
        
        # Verification metrics
        vm = metrics['verification_metrics']
        self.stdout.write(f"  - Verification rate: {vm['verification_rate']:.1f}%")
        self.stdout.write(f"  - Average verification time: {vm['avg_verification_time_hours']:.1f} hours")
        self.stdout.write(f"  - Pending over 24h: {vm['pending_over_24h']}")
        
        # Payment metrics
        pm = metrics['payment_metrics']
        self.stdout.write(f"  - Payment completion rate: {pm['completion_rate']:.1f}%")
        self.stdout.write(f"  - Average completion time: {pm['avg_completion_days']:.1f} days")
        self.stdout.write(f"  - Overdue deals: {pm['overdue_deals']}")
        
        # Workflow efficiency
        we = metrics['workflow_efficiency']
        self.stdout.write(f"  - Workflow efficiency score: {we['efficiency_score']:.1f}%")
        self.stdout.write(f"  - Stuck deals: {we['stuck_deals']} ({we['stuck_percentage']:.1f}%)")
        
        # Bottlenecks
        if metrics['bottleneck_analysis']:
            self.stdout.write("  Bottlenecks identified:")
            for bottleneck in metrics['bottleneck_analysis']:
                self.stdout.write(f"    - [{bottleneck['severity'].upper()}] {bottleneck['description']}")
    
    def _display_user_analytics(self, analytics):
        """Display user activity analytics"""
        self.stdout.write(f"\nUser Activity Analytics:")
        
        summary = analytics['summary']
        self.stdout.write(f"  - Total users: {summary['total_users']}")
        self.stdout.write(f"  - Active users (period): {summary['active_users_period']}")
        self.stdout.write(f"  - New users (period): {summary['new_users_period']}")
        self.stdout.write(f"  - OTP usage (period): {summary['otp_usage_period']}")
        
        if self.verbose and analytics['role_assignment_trends']:
            self.stdout.write("  Role distribution:")
            for role_trend in analytics['role_assignment_trends'][:5]:
                self.stdout.write(f"    - {role_trend['role__name']}: {role_trend['count']} users")
    
    def _generate_comprehensive_report(self, organization, days):
        """Generate comprehensive optimization report"""
        self.stdout.write("Generating comprehensive optimization report...")
        
        report_data = {
            'organization': organization.name if organization else 'All Organizations',
            'analysis_period_days': days,
            'generated_at': timezone.now().isoformat()
        }
        
        # Get deal workflow metrics
        deal_metrics = EnhancedDealWorkflowOptimizer.get_workflow_performance_metrics(
            organization=organization,
            days=days
        )
        report_data['deal_workflow_metrics'] = deal_metrics
        
        # Get user analytics (only for specific organization)
        if organization:
            user_analytics = UserOrganizationOptimizer.add_user_activity_tracking(
                organization=organization,
                days=days
            )
            report_data['user_activity_analytics'] = user_analytics
        
        # Generate recommendations
        recommendations = []
        
        # Deal workflow recommendations
        if deal_metrics['verification_metrics']['verification_rate'] < 80:
            recommendations.append({
                'category': 'deal_workflow',
                'priority': 'high',
                'issue': f"Low verification rate ({deal_metrics['verification_metrics']['verification_rate']:.1f}%)",
                'recommendation': 'Implement automated verification rules and provide verification team training'
            })
        
        if deal_metrics['workflow_efficiency']['efficiency_score'] < 70:
            recommendations.append({
                'category': 'deal_workflow',
                'priority': 'medium',
                'issue': f"Low workflow efficiency ({deal_metrics['workflow_efficiency']['efficiency_score']:.1f}%)",
                'recommendation': 'Optimize deal state transitions and reduce workflow bottlenecks'
            })
        
        report_data['recommendations'] = recommendations
        
        # Display report summary
        self.stdout.write(f"\nOptimization Report Summary:")
        self.stdout.write(f"  - Organization: {report_data['organization']}")
        self.stdout.write(f"  - Analysis period: {days} days")
        self.stdout.write(f"  - Total recommendations: {len(recommendations)}")
        
        if recommendations:
            self.stdout.write("  Key recommendations:")
            for rec in recommendations:
                self.stdout.write(f"    - [{rec['priority'].upper()}] {rec['issue']}")
        
        # Save report to file if verbose
        if self.verbose:
            import json
            filename = f"business_logic_optimization_report_{timezone.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            self.stdout.write(f"  - Detailed report saved to: {filename}")
        
        self.stdout.write(self.style.SUCCESS("Report generation completed!"))