"""
Django management command for commission performance optimization
Task 5.3.2: Optimize commission calculation performance
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta
from decimal import Decimal
import json

from apps.commission.calculation_optimizer import (
    CommissionCalculationOptimizer, 
    CommissionPerformanceOptimizer,
    CommissionAuditTrail
)
from apps.commission.models import Commission
from apps.organization.models import Organization
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):
    help = 'Optimize commission calculation performance with caching and monitoring'

    def add_arguments(self, parser):
        parser.add_argument(
            '--organization',
            type=str,
            help='Organization name or ID to optimize (default: all organizations)'
        )
        
        parser.add_argument(
            '--operation',
            type=str,
            choices=['optimize', 'monitor', 'warm_cache', 'bulk_optimize', 'analyze'],
            default='optimize',
            help='Operation to perform'
        )
        
        parser.add_argument(
            '--batch-size',
            type=int,
            default=100,
            help='Batch size for bulk operations'
        )
        
        parser.add_argument(
            '--time-period',
            type=int,
            default=24,
            help='Time period in hours for monitoring'
        )
        
        parser.add_argument(
            '--users',
            nargs='*',
            help='Specific user IDs to optimize (default: all active users)'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Run in dry-run mode without making changes'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

    def handle(self, *args, **options):
        self.verbose = options['verbose']
        operation = options['operation']
        
        try:
            # Get organizations to process
            organizations = self.get_organizations(options['organization'])
            
            if not organizations:
                raise CommandError('No organizations found to process')
            
            self.stdout.write(
                self.style.SUCCESS(f'Processing {len(organizations)} organization(s) with operation: {operation}')
            )
            
            # Process each organization
            for organization in organizations:
                self.stdout.write(f'\nProcessing organization: {organization.name}')
                
                try:
                    if operation == 'optimize':
                        result = self.optimize_commissions(organization, options)
                    elif operation == 'monitor':
                        result = self.monitor_performance(organization, options)
                    elif operation == 'warm_cache':
                        result = self.warm_caches(organization, options)
                    elif operation == 'bulk_optimize':
                        result = self.bulk_optimize(organization, options)
                    elif operation == 'analyze':
                        result = self.analyze_performance(organization, options)
                    
                    # Display results
                    self.display_results(operation, result, organization)
                    
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f'Error processing {organization.name}: {str(e)}')
                    )
                    if self.verbose:
                        import traceback
                        self.stdout.write(traceback.format_exc())
                    continue
            
            self.stdout.write(
                self.style.SUCCESS(f'\nCommission performance optimization completed')
            )
            
        except Exception as e:
            raise CommandError(f'Command failed: {str(e)}')

    def get_organizations(self, org_filter):
        """Get organizations to process"""
        if not org_filter:
            return Organization.objects.filter(is_active=True)
        
        # Try to get by ID first
        try:
            org_id = int(org_filter)
            return Organization.objects.filter(id=org_id, is_active=True)
        except ValueError:
            # Try to get by name
            return Organization.objects.filter(
                name__icontains=org_filter, 
                is_active=True
            )

    def optimize_commissions(self, organization, options):
        """Optimize frequently calculated commissions"""
        self.stdout.write('  Optimizing frequent calculations...')
        
        result = CommissionPerformanceOptimizer.optimize_frequent_calculations(
            organization,
            recalculate_threshold_hours=options['time_period']
        )
        
        return result

    def monitor_performance(self, organization, options):
        """Monitor commission calculation performance"""
        self.stdout.write('  Monitoring performance...')
        
        result = CommissionPerformanceOptimizer.monitor_commission_calculation_performance(
            organization,
            time_period_hours=options['time_period']
        )
        
        return result

    def warm_caches(self, organization, options):
        """Warm commission calculation caches"""
        self.stdout.write('  Warming caches...')
        
        user_ids = None
        if options['users']:
            try:
                user_ids = [int(uid) for uid in options['users']]
            except ValueError:
                self.stdout.write(
                    self.style.WARNING('Invalid user IDs provided, using all users')
                )
        
        result = CommissionPerformanceOptimizer.warm_commission_caches(
            organization,
            priority_users=user_ids
        )
        
        return result

    def bulk_optimize(self, organization, options):
        """Bulk optimize commission calculations"""
        self.stdout.write('  Performing bulk optimization...')
        
        user_ids = None
        if options['users']:
            try:
                user_ids = [int(uid) for uid in options['users']]
            except ValueError:
                self.stdout.write(
                    self.style.WARNING('Invalid user IDs provided, using all users')
                )
        
        result = CommissionPerformanceOptimizer.bulk_optimize_calculations(
            organization,
            user_ids=user_ids,
            batch_size=options['batch_size']
        )
        
        return result

    def analyze_performance(self, organization, options):
        """Analyze commission calculation performance"""
        self.stdout.write('  Analyzing performance...')
        
        # Get comprehensive analytics
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=options['time_period'])
        
        analytics = CommissionCalculationOptimizer.get_commission_analytics(
            organization, start_date, end_date
        )
        
        # Get performance monitoring data
        performance_data = CommissionPerformanceOptimizer.monitor_commission_calculation_performance(
            organization, options['time_period']
        )
        
        return {
            'analytics': analytics,
            'performance_monitoring': performance_data
        }

    def display_results(self, operation, result, organization):
        """Display operation results"""
        if operation == 'optimize':
            self.display_optimization_results(result)
        elif operation == 'monitor':
            self.display_monitoring_results(result)
        elif operation == 'warm_cache':
            self.display_cache_warming_results(result)
        elif operation == 'bulk_optimize':
            self.display_bulk_optimization_results(result)
        elif operation == 'analyze':
            self.display_analysis_results(result)

    def display_optimization_results(self, result):
        """Display optimization results"""
        summary = result['optimization_summary']
        
        self.stdout.write(
            f'  ✓ Optimized: {summary["commissions_optimized"]} commissions'
        )
        self.stdout.write(
            f'  ✓ Cache hits: {summary["cache_hits"]}'
        )
        self.stdout.write(
            f'  ✓ Total time: {summary["total_optimization_time_ms"]:.2f}ms'
        )
        if summary['average_calculation_time_ms'] > 0:
            self.stdout.write(
                f'  ✓ Average calc time: {summary["average_calculation_time_ms"]:.2f}ms'
            )
        
        # Show recommendations
        if result.get('recommendations'):
            self.stdout.write('  📋 Recommendations:')
            for rec in result['recommendations']:
                self.stdout.write(
                    f'    • {rec["recommendation"]} (Priority: {rec["priority"]})'
                )

    def display_monitoring_results(self, result):
        """Display monitoring results"""
        stats = result['commission_statistics']
        
        self.stdout.write(
            f'  📊 Total calculations: {stats["total_calculations"]}'
        )
        self.stdout.write(
            f'  📊 Unique users: {stats["unique_users"]}'
        )
        self.stdout.write(
            f'  📊 Calculations per hour: {stats["calculations_per_hour"]:.2f}'
        )
        
        # Show bottlenecks
        if result.get('bottlenecks'):
            self.stdout.write('  ⚠️  Performance bottlenecks:')
            for bottleneck in result['bottlenecks']:
                severity_style = self.style.ERROR if bottleneck['severity'] == 'high' else self.style.WARNING
                self.stdout.write(
                    severity_style(f'    • {bottleneck["description"]}')
                )
        
        # Show recommendations
        if result.get('recommendations'):
            self.stdout.write('  📋 Recommendations:')
            for rec in result['recommendations']:
                priority_style = self.style.ERROR if rec['priority'] == 'critical' else self.style.WARNING
                self.stdout.write(
                    priority_style(f'    • {rec["recommendation"]}')
                )

    def display_cache_warming_results(self, result):
        """Display cache warming results"""
        summary = result['cache_warming_summary']
        
        self.stdout.write(
            f'  🔥 Caches warmed: {summary["caches_warmed"]}'
        )
        self.stdout.write(
            f'  🔥 Users processed: {summary["users_processed"]}'
        )
        self.stdout.write(
            f'  🔥 Total time: {summary["total_warming_time_ms"]:.2f}ms'
        )
        if summary['average_time_per_cache_ms'] > 0:
            self.stdout.write(
                f'  🔥 Average time per cache: {summary["average_time_per_cache_ms"]:.2f}ms'
            )

    def display_bulk_optimization_results(self, result):
        """Display bulk optimization results"""
        summary = result['bulk_optimization_summary']
        analysis = result.get('performance_analysis', {})
        
        self.stdout.write(
            f'  🚀 Total commissions: {summary["total_commissions"]}'
        )
        self.stdout.write(
            f'  🚀 Processed: {summary["processed_commissions"]}'
        )
        self.stdout.write(
            f'  🚀 Batches: {summary["batch_count"]}'
        )
        self.stdout.write(
            f'  🚀 Total time: {summary["total_time_ms"]:.2f}ms'
        )
        self.stdout.write(
            f'  🚀 Throughput: {summary["throughput_per_second"]:.2f} commissions/sec'
        )
        
        if analysis.get('performance_consistency'):
            self.stdout.write(
                f'  🚀 Performance consistency: {analysis["performance_consistency"]:.1f}%'
            )

    def display_analysis_results(self, result):
        """Display analysis results"""
        analytics = result['analytics']
        performance = result['performance_monitoring']
        
        # Analytics summary
        analytics_summary = analytics['summary']
        self.stdout.write('  📈 Analytics Summary:')
        self.stdout.write(
            f'    • Total commissions: {analytics_summary["total_commissions"]}'
        )
        self.stdout.write(
            f'    • Total sales: ${analytics_summary["total_sales"]:,.2f}'
        )
        self.stdout.write(
            f'    • Total commission amount: ${analytics_summary["total_commission_amount"]:,.2f}'
        )
        self.stdout.write(
            f'    • Average commission rate: {analytics_summary["avg_commission_rate"]:.2f}%'
        )
        
        # Performance summary
        perf_stats = performance['commission_statistics']
        self.stdout.write('  ⚡ Performance Summary:')
        self.stdout.write(
            f'    • Recent calculations: {perf_stats["total_calculations"]}'
        )
        self.stdout.write(
            f'    • Calculations per hour: {perf_stats["calculations_per_hour"]:.2f}'
        )
        
        # Top performers
        if analytics.get('top_performers'):
            self.stdout.write('  🏆 Top Performers:')
            for i, performer in enumerate(analytics['top_performers'][:5], 1):
                self.stdout.write(
                    f'    {i}. {performer["user_name"]}: ${performer["total_sales"]:,.2f} sales, '
                    f'${performer["total_commission"]:,.2f} commission'
                )
        
        # Show detailed results if verbose
        if self.verbose:
            self.stdout.write('\n  📋 Detailed Results:')
            self.stdout.write(json.dumps(result, indent=2, default=str))
