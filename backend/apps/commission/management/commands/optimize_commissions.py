"""
Commission Optimization Management Command
Provides tools for commission calculation optimization and maintenance
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
from commission.models import Commission
from commission.calculation_optimizer import CommissionCalculationOptimizer, CommissionAuditTrail
from apps.organization.models import Organization
from apps.authentication.models import User
import logging

logger = logging.getLogger('commission')

class Command(BaseCommand):
    help = 'Commission calculation optimization and maintenance tools'

    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=['reconcile', 'fix-discrepancies', 'analytics', 'cache-warmup', 'cleanup'],
            required=True,
            help='Action to perform'
        )
        
        parser.add_argument(
            '--organization-id',
            type=int,
            help='Organization ID to process (optional, processes all if not specified)'
        )
        
        parser.add_argument(
            '--start-date',
            type=str,
            help='Start date in YYYY-MM-DD format (defaults to current month start)'
        )
        
        parser.add_argument(
            '--end-date',
            type=str,
            help='End date in YYYY-MM-DD format (defaults to current date)'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Perform a dry run without making changes'
        )
        
        parser.add_argument(
            '--fix-discrepancies',
            action='store_true',
            help='Actually fix discrepancies (not dry run)'
        )

    def handle(self, *args, **options):
        action = options['action']
        organization_id = options.get('organization_id')
        dry_run = options.get('dry_run', True)
        
        # Parse dates
        start_date = self.parse_date(options.get('start_date'))
        end_date = self.parse_date(options.get('end_date'))
        
        if not start_date:
            start_date = timezone.now().replace(day=1).date()
        if not end_date:
            end_date = timezone.now().date()
        
        self.stdout.write(f"Running commission optimization: {action}")
        self.stdout.write(f"Date range: {start_date} to {end_date}")
        
        # Get organizations to process
        if organization_id:
            organizations = Organization.objects.filter(id=organization_id)
            if not organizations.exists():
                self.stdout.write(
                    self.style.ERROR(f'Organization with ID {organization_id} not found')
                )
                return
        else:
            organizations = Organization.objects.all()
        
        for organization in organizations:
            self.stdout.write(f"\nProcessing organization: {organization.name}")
            
            try:
                if action == 'reconcile':
                    self.reconcile_commissions(organization, start_date, end_date)
                elif action == 'fix-discrepancies':
                    self.fix_discrepancies(organization, start_date, end_date, not options.get('fix_discrepancies', False))
                elif action == 'analytics':
                    self.show_analytics(organization, start_date, end_date)
                elif action == 'cache-warmup':
                    self.warmup_caches(organization, start_date, end_date)
                elif action == 'cleanup':
                    self.cleanup_old_data(organization, start_date, end_date)
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error processing {organization.name}: {str(e)}')
                )
                logger.error(f"Commission optimization error for {organization.name}: {str(e)}")

    def parse_date(self, date_str):
        """Parse date string in YYYY-MM-DD format"""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            self.stdout.write(
                self.style.ERROR(f'Invalid date format: {date_str}. Use YYYY-MM-DD')
            )
            return None

    def reconcile_commissions(self, organization, start_date, end_date):
        """Reconcile commission calculations with actual sales data"""
        self.stdout.write(f"  Reconciling commissions...")
        
        result = CommissionCalculationOptimizer.get_commission_reconciliation_data(
            organization=organization,
            start_date=start_date,
            end_date=end_date
        )
        
        summary = result['summary']
        self.stdout.write(f"    Total commissions: {summary['total_commissions']}")
        self.stdout.write(f"    Discrepancies found: {summary['discrepancies_found']}")
        self.stdout.write(f"    Total recorded sales: ${summary['total_recorded_sales']:,.2f}")
        self.stdout.write(f"    Total actual sales: ${summary['total_actual_sales']:,.2f}")
        
        if summary['discrepancies_found'] > 0:
            self.stdout.write(
                self.style.WARNING(f"    Found {summary['discrepancies_found']} discrepancies")
            )
            
            for discrepancy in result['discrepancies'][:5]:  # Show first 5
                self.stdout.write(
                    f"      {discrepancy['user_email']}: "
                    f"Recorded ${discrepancy['recorded_sales']:,.2f}, "
                    f"Actual ${discrepancy['actual_sales']:,.2f}, "
                    f"Diff ${discrepancy['discrepancy']:,.2f}"
                )
        else:
            self.stdout.write(self.style.SUCCESS("    No discrepancies found"))

    def fix_discrepancies(self, organization, start_date, end_date, dry_run=True):
        """Fix commission calculation discrepancies"""
        action_text = "Would fix" if dry_run else "Fixing"
        self.stdout.write(f"  {action_text} commission discrepancies...")
        
        result = CommissionCalculationOptimizer.auto_fix_commission_discrepancies(
            organization=organization,
            start_date=start_date,
            end_date=end_date,
            dry_run=dry_run
        )
        
        summary = result['summary']
        self.stdout.write(f"    Total discrepancies: {summary['total_discrepancies']}")
        self.stdout.write(f"    Successfully fixed: {summary['successfully_fixed']}")
        self.stdout.write(f"    Failed to fix: {summary['failed_to_fix']}")
        
        if result['fixed_commissions']:
            for fix in result['fixed_commissions'][:5]:  # Show first 5
                self.stdout.write(
                    f"      {fix['user_email']}: "
                    f"${fix['old_sales']:,.2f} → ${fix['new_sales']:,.2f}"
                )
        
        if not dry_run and summary['successfully_fixed'] > 0:
            self.stdout.write(
                self.style.SUCCESS(f"    Fixed {summary['successfully_fixed']} discrepancies")
            )

    def show_analytics(self, organization, start_date, end_date):
        """Show commission analytics"""
        self.stdout.write(f"  Generating commission analytics...")
        
        result = CommissionCalculationOptimizer.get_commission_analytics(
            organization=organization,
            start_date=start_date,
            end_date=end_date
        )
        
        summary = result['summary']
        self.stdout.write(f"    Total commissions: {summary['total_commissions']}")
        self.stdout.write(f"    Total sales: ${summary['total_sales']:,.2f}")
        self.stdout.write(f"    Total commission amount: ${summary['total_commission_amount']:,.2f}")
        self.stdout.write(f"    Average commission rate: {summary['avg_commission_rate']:.2f}%")
        self.stdout.write(f"    Average sales per person: ${summary['avg_sales_per_person']:,.2f}")
        
        # Show top performers
        if result['top_performers']:
            self.stdout.write("    Top performers:")
            for performer in result['top_performers'][:3]:
                self.stdout.write(
                    f"      {performer['user_name']}: "
                    f"${performer['total_sales']:,.2f} sales, "
                    f"${performer['total_commission']:,.2f} commission"
                )

    def warmup_caches(self, organization, start_date, end_date):
        """Warm up commission calculation caches"""
        self.stdout.write(f"  Warming up commission caches...")
        
        # Get all salespeople
        salespeople = User.objects.filter(
            organization=organization,
            role__name__in=['Salesperson', 'Senior Salesperson'],
            is_active=True
        )
        
        # Warm up individual calculations
        for user in salespeople:
            try:
                CommissionCalculationOptimizer.calculate_user_commission(
                    user=user,
                    start_date=start_date,
                    end_date=end_date,
                    organization=organization,
                    use_cache=True
                )
            except Exception as e:
                logger.error(f"Failed to warm cache for user {user.email}: {str(e)}")
        
        # Warm up bulk calculation
        try:
            CommissionCalculationOptimizer.bulk_calculate_commissions(
                organization=organization,
                start_date=start_date,
                end_date=end_date
            )
        except Exception as e:
            logger.error(f"Failed to warm bulk cache: {str(e)}")
        
        # Warm up analytics
        try:
            CommissionCalculationOptimizer.get_commission_analytics(
                organization=organization,
                start_date=start_date,
                end_date=end_date
            )
        except Exception as e:
            logger.error(f"Failed to warm analytics cache: {str(e)}")
        
        self.stdout.write(
            self.style.SUCCESS(f"    Cache warmup completed for {salespeople.count()} users")
        )

    def cleanup_old_data(self, organization, start_date, end_date):
        """Clean up old commission data and audit logs"""
        self.stdout.write(f"  Cleaning up old commission data...")
        
        # Find old commission records (older than 2 years)
        cutoff_date = timezone.now().date() - timedelta(days=730)
        
        old_commissions = Commission.objects.filter(
            organization=organization,
            created_at__date__lt=cutoff_date
        )
        
        count = old_commissions.count()
        self.stdout.write(f"    Found {count} old commission records (before {cutoff_date})")
        
        if count > 0:
            # In a real implementation, you might want to archive rather than delete
            self.stdout.write("    Consider archiving old records instead of deletion")
        
        self.stdout.write(self.style.SUCCESS("    Cleanup analysis completed"))