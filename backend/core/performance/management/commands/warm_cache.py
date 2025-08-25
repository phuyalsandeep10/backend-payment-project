"""
Cache Warming Management Command - Task 4.1.3

Django management command for cache warming operations,
including predictive warming and background refresh setup.
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from core.performance.cache_warming_system import (
    cache_warming_manager,
    OrganizationDataSource,
    UserDataSource,
    warm_organization_data,
    warm_user_data,
    warm_critical_data
)
import time
import json
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Cache warming management command
    Task 4.1.3: Cache warming automation
    """
    
    help = 'Manage cache warming operations and predictive caching'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            choices=['warm', 'status', 'critical', 'organization', 'user', 'predictive'],
            default='status',
            help='Action to perform (default: status)'
        )
        
        parser.add_argument(
            '--organization-id',
            type=int,
            help='Organization ID for organization-specific warming'
        )
        
        parser.add_argument(
            '--user-id',
            type=int,
            help='User ID for user-specific warming'
        )
        
        parser.add_argument(
            '--data-types',
            nargs='*',
            help='Specific data types to warm (e.g., dashboard_stats, deal_list)'
        )
        
        parser.add_argument(
            '--enable-predictive',
            action='store_true',
            help='Enable predictive warming'
        )
        
        parser.add_argument(
            '--disable-predictive',
            action='store_true',
            help='Disable predictive warming'
        )
        
        parser.add_argument(
            '--threshold',
            type=int,
            default=3,
            help='Access threshold for predictive warming (default: 3)'
        )
        
        parser.add_argument(
            '--prediction-window',
            type=int,
            default=2,
            help='Prediction window in hours (default: 2)'
        )
        
        parser.add_argument(
            '--parallel-jobs',
            type=int,
            default=4,
            help='Number of parallel warming jobs (default: 4)'
        )
        
        parser.add_argument(
            '--simulate',
            action='store_true',
            help='Simulate warming without actually warming cache'
        )
    
    def handle(self, *args, **options):
        try:
            action = options['action']
            
            self.stdout.write(
                self.style.SUCCESS(f'🔥 Starting cache warming - Action: {action.upper()}')
            )
            
            if action == 'status':
                self._show_warming_status()
            elif action == 'warm':
                self._perform_general_warming(options)
            elif action == 'critical':
                self._warm_critical_cache(options)
            elif action == 'organization':
                self._warm_organization_cache(options)
            elif action == 'user':
                self._warm_user_cache(options)
            elif action == 'predictive':
                self._manage_predictive_warming(options)
            
            self.stdout.write(
                self.style.SUCCESS('✅ Cache warming operation completed successfully!')
            )
            
        except Exception as e:
            logger.error(f"Error in cache warming command: {e}")
            raise CommandError(f'Cache warming failed: {str(e)}')
    
    def _show_warming_status(self):
        """Show current cache warming status"""
        
        self.stdout.write(self.style.SUCCESS('\n🔥 Cache Warming Status'))
        self.stdout.write('=' * 60)
        
        status = cache_warming_manager.get_warming_status()
        metrics = status['metrics']
        
        # System status
        self.stdout.write(f"Warming Enabled: {'✅ YES' if status['warming_enabled'] else '❌ NO'}")
        self.stdout.write(f"Predictive Warming: {'✅ YES' if status['predictive_warming_enabled'] else '❌ NO'}")
        self.stdout.write(f"Background Refresh: {'✅ YES' if status['background_refresh_enabled'] else '❌ NO'}")
        
        # Job statistics
        self.stdout.write(f"\nJob Statistics:")
        self.stdout.write(f"  Total Registered Jobs: {status['total_registered_jobs']:,}")
        self.stdout.write(f"  Active Jobs: {status['active_jobs']:,}")
        self.stdout.write(f"  Access Patterns Tracked: {status['access_patterns_tracked']:,}")
        
        # Queue status
        queue_sizes = status['queue_sizes']
        total_queued = status['total_queued']
        self.stdout.write(f"\nQueue Status (Total: {total_queued:,}):")
        self.stdout.write(f"  Critical: {queue_sizes['critical']:,}")
        self.stdout.write(f"  High: {queue_sizes['high']:,}")
        self.stdout.write(f"  Normal: {queue_sizes['normal']:,}")
        self.stdout.write(f"  Low: {queue_sizes['low']:,}")
        
        # Performance metrics
        self.stdout.write(f"\nPerformance Metrics:")
        self.stdout.write(f"  Total Warming Jobs: {metrics.total_warming_jobs:,}")
        self.stdout.write(f"  Successful Warmings: {metrics.successful_warmings:,}")
        self.stdout.write(f"  Failed Warmings: {metrics.failed_warmings:,}")
        
        if metrics.total_warming_jobs > 0:
            success_rate = (metrics.successful_warmings / metrics.total_warming_jobs) * 100
            self.stdout.write(f"  Success Rate: {success_rate:.1f}%")
        
        self.stdout.write(f"  Average Warming Time: {metrics.avg_warming_time:.3f}s")
        self.stdout.write(f"  Total Data Warmed: {self._format_bytes(metrics.total_data_warmed)}")
        self.stdout.write(f"  Predictive Hits: {metrics.predictive_hits:,}")
        
        # Health assessment
        self._assess_warming_health(status, metrics)
        
        self.stdout.write('=' * 60)
    
    def _perform_general_warming(self, options):
        """Perform general cache warming"""
        
        self.stdout.write("Performing general cache warming...")
        
        if options['simulate']:
            self.stdout.write(self.style.WARNING("SIMULATION MODE - No actual warming"))
            return
        
        start_time = time.time()
        results = {
            'critical': None,
            'organizations': [],
            'users': []
        }
        
        # Warm critical cache
        self.stdout.write("Warming critical cache...")
        results['critical'] = warm_critical_data()
        
        # Warm common organization data (first 10 active organizations)
        try:
            from apps.organization.models import Organization
            
            active_orgs = Organization.objects.filter(is_active=True)[:10]
            
            for org in active_orgs:
                self.stdout.write(f"  Warming organization {org.id}...")
                result = warm_organization_data(org.id)
                results['organizations'].append(result)
                
                if not options.get('quiet', False):
                    if result['success']:
                        self.stdout.write(
                            f"    ✅ {result['successful_keys']}/{result['total_keys']} keys warmed"
                        )
                    else:
                        self.stdout.write(f"    ❌ Failed: {result.get('error', 'Unknown error')}")
                        
        except Exception as e:
            self.stdout.write(f"  ⚠️  Could not warm organization caches: {e}")
        
        # Summary
        total_time = time.time() - start_time
        self._show_warming_summary(results, total_time)
    
    def _warm_critical_cache(self, options):
        """Warm critical cache entries"""
        
        self.stdout.write("Warming critical cache entries...")
        
        if options['simulate']:
            self.stdout.write(self.style.WARNING("SIMULATION MODE - No actual warming"))
            return
        
        result = warm_critical_data()
        
        if result['success']:
            self.stdout.write(
                self.style.SUCCESS(
                    f"✅ Critical cache warmed: {result['successful_jobs']}/{result['total_jobs']} jobs "
                    f"in {result['execution_time']:.3f}s"
                )
            )
            
            # Show job details
            for job_result in result.get('results', []):
                key = job_result['key']
                job_success = job_result['result']['success']
                status = "✅" if job_success else "❌"
                self.stdout.write(f"  {status} {key}")
                
        else:
            self.stdout.write(
                self.style.ERROR(f"❌ Critical cache warming failed: {result['error']}")
            )
    
    def _warm_organization_cache(self, options):
        """Warm organization-specific cache"""
        
        org_id = options.get('organization_id')
        if not org_id:
            raise CommandError('--organization-id is required for organization warming')
        
        data_types = options.get('data_types')
        
        self.stdout.write(f"Warming cache for organization {org_id}...")
        
        if options['simulate']:
            self.stdout.write(self.style.WARNING("SIMULATION MODE - No actual warming"))
            return
        
        result = warm_organization_data(org_id)
        
        if result['success']:
            self.stdout.write(
                self.style.SUCCESS(
                    f"✅ Organization {org_id} cache warmed: "
                    f"{result['successful_keys']}/{result['total_keys']} keys "
                    f"in {result['execution_time']:.3f}s"
                )
            )
            
            # Show details
            for key_result in result.get('results', []):
                key = key_result['key']
                key_success = key_result['result']['success']
                status = "✅" if key_success else "❌"
                
                if key_success and 'data_size' in key_result['result']:
                    size = self._format_bytes(key_result['result']['data_size'])
                    self.stdout.write(f"  {status} {key} ({size})")
                else:
                    self.stdout.write(f"  {status} {key}")
                    
        else:
            self.stdout.write(
                self.style.ERROR(f"❌ Organization cache warming failed: {result['error']}")
            )
    
    def _warm_user_cache(self, options):
        """Warm user-specific cache"""
        
        user_id = options.get('user_id')
        if not user_id:
            raise CommandError('--user-id is required for user warming')
        
        data_types = options.get('data_types')
        
        self.stdout.write(f"Warming cache for user {user_id}...")
        
        if options['simulate']:
            self.stdout.write(self.style.WARNING("SIMULATION MODE - No actual warming"))
            return
        
        result = warm_user_data(user_id)
        
        if result['success']:
            self.stdout.write(
                self.style.SUCCESS(
                    f"✅ User {user_id} cache warmed: "
                    f"{result['successful_keys']}/{result['total_keys']} keys "
                    f"in {result['execution_time']:.3f}s"
                )
            )
            
            # Show details
            for key_result in result.get('results', []):
                key = key_result['key']
                key_success = key_result['result']['success']
                status = "✅" if key_success else "❌"
                self.stdout.write(f"  {status} {key}")
                    
        else:
            self.stdout.write(
                self.style.ERROR(f"❌ User cache warming failed: {result['error']}")
            )
    
    def _manage_predictive_warming(self, options):
        """Manage predictive warming settings"""
        
        if options['enable_predictive']:
            threshold = options['threshold']
            window = options['prediction_window']
            
            cache_warming_manager.enable_predictive_warming(
                access_threshold=threshold,
                prediction_window_hours=window
            )
            
            self.stdout.write(
                self.style.SUCCESS(
                    f"✅ Predictive warming enabled (threshold: {threshold}, window: {window}h)"
                )
            )
            
        elif options['disable_predictive']:
            cache_warming_manager.predictive_warming_enabled = False
            self.stdout.write(self.style.SUCCESS("✅ Predictive warming disabled"))
        
        else:
            # Show predictive warming status
            status = cache_warming_manager.get_warming_status()
            
            self.stdout.write(f"\nPredictive Warming Status:")
            self.stdout.write(f"  Enabled: {'✅ YES' if status['predictive_warming_enabled'] else '❌ NO'}")
            
            if hasattr(cache_warming_manager, 'access_threshold'):
                self.stdout.write(f"  Access Threshold: {cache_warming_manager.access_threshold}")
                
            if hasattr(cache_warming_manager, 'prediction_window'):
                self.stdout.write(f"  Prediction Window: {cache_warming_manager.prediction_window}")
            
            self.stdout.write(f"  Access Patterns Tracked: {status['access_patterns_tracked']:,}")
            self.stdout.write(f"  Predictive Hits: {status['metrics'].predictive_hits:,}")
    
    def _assess_warming_health(self, status, metrics):
        """Assess and display warming system health"""
        
        self.stdout.write(f"\n🏥 System Health Assessment:")
        
        # Success rate assessment
        if metrics.total_warming_jobs > 0:
            success_rate = (metrics.successful_warmings / metrics.total_warming_jobs) * 100
            
            if success_rate >= 95:
                self.stdout.write("  ✅ Success Rate: EXCELLENT")
            elif success_rate >= 85:
                self.stdout.write("  ⚠️  Success Rate: GOOD") 
            else:
                self.stdout.write("  ❌ Success Rate: NEEDS ATTENTION")
        
        # Queue health
        total_queued = status['total_queued']
        if total_queued == 0:
            self.stdout.write("  ✅ Queue Status: HEALTHY")
        elif total_queued < 100:
            self.stdout.write("  ✅ Queue Status: NORMAL")
        elif total_queued < 500:
            self.stdout.write("  ⚠️  Queue Status: ELEVATED")
        else:
            self.stdout.write("  ❌ Queue Status: CRITICAL")
        
        # Performance assessment
        if metrics.avg_warming_time < 0.1:
            self.stdout.write("  ✅ Performance: EXCELLENT")
        elif metrics.avg_warming_time < 0.5:
            self.stdout.write("  ✅ Performance: GOOD")
        else:
            self.stdout.write("  ⚠️  Performance: SLOW")
        
        # Predictive effectiveness
        if status['predictive_warming_enabled']:
            if metrics.predictive_hits > 0:
                self.stdout.write("  ✅ Predictive: ACTIVE")
            else:
                self.stdout.write("  ⚠️  Predictive: NO HITS YET")
        else:
            self.stdout.write("  ❌ Predictive: DISABLED")
    
    def _show_warming_summary(self, results, total_time):
        """Show summary of warming operations"""
        
        self.stdout.write(f"\n📊 Warming Summary:")
        
        # Critical cache
        critical_result = results.get('critical')
        if critical_result:
            if critical_result['success']:
                self.stdout.write(
                    f"  Critical: ✅ {critical_result['successful_jobs']}/{critical_result['total_jobs']} jobs"
                )
            else:
                self.stdout.write("  Critical: ❌ Failed")
        
        # Organizations
        org_results = results.get('organizations', [])
        if org_results:
            successful_orgs = sum(1 for r in org_results if r['success'])
            total_keys = sum(r.get('total_keys', 0) for r in org_results)
            successful_keys = sum(r.get('successful_keys', 0) for r in org_results)
            
            self.stdout.write(
                f"  Organizations: ✅ {successful_orgs}/{len(org_results)} orgs, "
                f"{successful_keys}/{total_keys} keys"
            )
        
        self.stdout.write(f"  Total Time: {total_time:.3f}s")
        
        # Recommendations
        if total_time > 30:
            self.stdout.write("  💡 Consider reducing warming scope or increasing parallel jobs")
        
        if any(not r['success'] for r in org_results if 'success' in r):
            self.stdout.write("  💡 Check logs for failed warming operations")
    
    def _format_bytes(self, bytes_count):
        """Format bytes for human readability"""
        if bytes_count == 0:
            return '0 B'
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        
        return f"{bytes_count:.1f} TB"
