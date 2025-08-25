"""
Management command for cache management operations
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.core.cache import cache
from datetime import timedelta
import logging

from core_config.strategic_cache_manager import StrategicCacheManager
from core_config.api_response_optimizer import APIResponseOptimizer, CacheWarmingManager

class Command(BaseCommand):
    help = 'Manage strategic caching and API response optimization'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=['warm', 'invalidate', 'status', 'clear', 'test'],
            required=True,
            help='Cache management action to perform'
        )
        
        parser.add_argument(
            '--organization',
            type=str,
            help='Organization name to target (if not provided, affects all organizations)'
        )
        
        parser.add_argument(
            '--cache-type',
            type=str,
            choices=['strategic', 'api', 'all'],
            default='all',
            help='Type of cache to manage'
        )
        
        parser.add_argument(
            '--user-id',
            type=int,
            help='Specific user ID for user-specific cache operations'
        )
        
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days for statistics caching'
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force operation without confirmation'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
    
    def handle(self, *args, **options):
        self.verbosity = options.get('verbosity', 1)
        self.verbose = options.get('verbose', False)
        
        action = options['action']
        organization_name = options.get('organization')
        cache_type = options['cache_type']
        user_id = options.get('user_id')
        days = options['days']
        force = options['force']
        
        # Get organization if specified
        organization = None
        if organization_name:
            try:
                from organization.models import Organization
                organization = Organization.objects.get(name=organization_name)
                self.stdout.write(f"Targeting organization: {organization.name}")
            except Organization.DoesNotExist:
                raise CommandError(f"Organization '{organization_name}' not found")
        else:
            self.stdout.write("Targeting all organizations")
        
        try:
            if action == 'warm':
                self._warm_caches(organization, cache_type, force)
            
            elif action == 'invalidate':
                self._invalidate_caches(organization, cache_type, user_id, force)
            
            elif action == 'status':
                self._show_cache_status(organization, cache_type)
            
            elif action == 'clear':
                self._clear_caches(organization, cache_type, force)
            
            elif action == 'test':
                self._test_cache_performance(organization, days)
            
            self.stdout.write(
                self.style.SUCCESS(f"Cache {action} operation completed successfully!")
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Cache operation failed: {str(e)}")
            )
            if self.verbose:
                import traceback
                self.stdout.write(traceback.format_exc())
            raise CommandError(f"Cache operation failed: {str(e)}")
    
    def _warm_caches(self, organization, cache_type, force):
        """Warm up caches"""
        if not force:
            confirm = input(f"This will warm {cache_type} caches. Continue? (y/N): ")
            if confirm.lower() != 'y':
                self.stdout.write("Operation cancelled")
                return
        
        self.stdout.write("Starting cache warming...")
        
        if organization:
            organizations = [organization]
        else:
            from organization.models import Organization
            organizations = Organization.objects.filter(is_active=True)
        
        for org in organizations:
            self.stdout.write(f"Warming caches for {org.name}...")
            
            if cache_type in ['strategic', 'all']:
                self.stdout.write("  - Warming strategic caches...")
                StrategicCacheManager.warm_organization_cache(org.id)
            
            if cache_type in ['api', 'all']:
                self.stdout.write("  - Warming API response caches...")
                APIResponseOptimizer.warm_frequently_accessed_caches(org.id)
            
            if self.verbose:
                self.stdout.write(f"    ✓ Cache warming completed for {org.name}")
        
        self.stdout.write(f"Cache warming completed for {len(organizations)} organizations")
    
    def _invalidate_caches(self, organization, cache_type, user_id, force):
        """Invalidate caches"""
        if not force:
            confirm = input(f"This will invalidate {cache_type} caches. Continue? (y/N): ")
            if confirm.lower() != 'y':
                self.stdout.write("Operation cancelled")
                return
        
        self.stdout.write("Starting cache invalidation...")
        
        if organization:
            organizations = [organization]
        else:
            from organization.models import Organization
            organizations = Organization.objects.filter(is_active=True)
        
        for org in organizations:
            self.stdout.write(f"Invalidating caches for {org.name}...")
            
            if cache_type in ['strategic', 'all']:
                self.stdout.write("  - Invalidating strategic caches...")
                StrategicCacheManager.invalidate_organization_related_caches(org.id)
            
            if cache_type in ['api', 'all']:
                self.stdout.write("  - Invalidating API response caches...")
                APIResponseOptimizer.invalidate_api_caches(
                    cache_pattern='all',
                    organization_id=org.id
                )
            
            if user_id:
                self.stdout.write(f"  - Invalidating user-specific caches for user {user_id}...")
                StrategicCacheManager.invalidate_user_related_caches(user_id, org.id)
                APIResponseOptimizer.invalidate_api_caches(
                    cache_pattern='dashboard',
                    organization_id=org.id,
                    user_id=user_id
                )
            
            if self.verbose:
                self.stdout.write(f"    ✓ Cache invalidation completed for {org.name}")
        
        self.stdout.write(f"Cache invalidation completed for {len(organizations)} organizations")
    
    def _show_cache_status(self, organization, cache_type):
        """Show cache status and statistics"""
        self.stdout.write("Cache Status Report")
        self.stdout.write("=" * 50)
        
        # Strategic cache statistics
        if cache_type in ['strategic', 'all']:
            self.stdout.write("\nStrategic Cache Status:")
            strategic_stats = StrategicCacheManager.get_cache_statistics()
            
            self.stdout.write(f"  - Cache Backend: {strategic_stats.get('cache_backend', 'Unknown')}")
            self.stdout.write(f"  - Cache Prefixes: {len(strategic_stats.get('cache_prefixes', {}))}")
            
            ttl_settings = strategic_stats.get('ttl_settings', {})
            self.stdout.write("  - TTL Settings:")
            for cache_name, ttl in ttl_settings.items():
                self.stdout.write(f"    - {cache_name}: {ttl} seconds ({ttl//60} minutes)")
        
        # API response cache statistics
        if cache_type in ['api', 'all']:
            self.stdout.write("\nAPI Response Cache Status:")
            api_stats = APIResponseOptimizer.get_cache_performance_metrics()
            
            self.stdout.write(f"  - Cache Hit Rate: {api_stats.get('cache_hit_rate', 0):.2%}")
            self.stdout.write(f"  - Cache Miss Rate: {api_stats.get('cache_miss_rate', 0):.2%}")
            self.stdout.write(f"  - Total Requests: {api_stats.get('total_requests', 0)}")
            
            ttl_settings = api_stats.get('ttl_settings', {})
            self.stdout.write("  - TTL Settings:")
            for cache_name, ttl in ttl_settings.items():
                self.stdout.write(f"    - {cache_name}: {ttl} seconds ({ttl//60} minutes)")
        
        # Organization-specific statistics
        if organization:
            self.stdout.write(f"\nOrganization-Specific Cache Data ({organization.name}):")
            
            # Check if organization data is cached
            org_data = StrategicCacheManager.get_organization_data(organization.id)
            if org_data:
                self.stdout.write("  ✓ Organization data cached")
                self.stdout.write(f"    - Cached at: {org_data.get('cached_at', 'Unknown')}")
                stats = org_data.get('statistics', {})
                self.stdout.write(f"    - Total users: {stats.get('total_users', 0)}")
                self.stdout.write(f"    - Total deals: {stats.get('total_deals', 0)}")
            else:
                self.stdout.write("  ✗ Organization data not cached")
            
            # Check role information cache
            role_info = StrategicCacheManager.get_role_information(organization.id)
            if role_info:
                self.stdout.write("  ✓ Role information cached")
                self.stdout.write(f"    - Roles count: {len(role_info.get('roles', []))}")
            else:
                self.stdout.write("  ✗ Role information not cached")
            
            # Check deal statistics cache
            deal_stats = StrategicCacheManager.get_deal_statistics(organization.id, 30)
            if deal_stats:
                self.stdout.write("  ✓ Deal statistics cached (30 days)")
                basic_stats = deal_stats.get('basic_stats', {})
                self.stdout.write(f"    - Total deals: {basic_stats.get('total_deals', 0)}")
                self.stdout.write(f"    - Verified deals: {basic_stats.get('verified_deals', 0)}")
            else:
                self.stdout.write("  ✗ Deal statistics not cached")
        
        self.stdout.write(f"\nReport generated at: {timezone.now().isoformat()}")
    
    def _clear_caches(self, organization, cache_type, force):
        """Clear all caches (use with extreme caution)"""
        if not force:
            self.stdout.write(
                self.style.WARNING("WARNING: This will clear ALL caches and may impact performance!")
            )
            confirm = input("Are you absolutely sure? Type 'CLEAR' to confirm: ")
            if confirm != 'CLEAR':
                self.stdout.write("Operation cancelled")
                return
        
        self.stdout.write("Clearing caches...")
        
        if cache_type in ['strategic', 'all']:
            self.stdout.write("  - Clearing strategic caches...")
            StrategicCacheManager.clear_all_strategic_caches()
        
        if cache_type in ['api', 'all']:
            self.stdout.write("  - Clearing API response caches...")
            # This would clear API-specific caches
            cache.clear()
        
        self.stdout.write("All caches cleared")
    
    def _test_cache_performance(self, organization, days):
        """Test cache performance"""
        self.stdout.write("Testing cache performance...")
        
        if not organization:
            from organization.models import Organization
            organization = Organization.objects.filter(is_active=True).first()
            if not organization:
                raise CommandError("No active organizations found for testing")
        
        self.stdout.write(f"Testing with organization: {organization.name}")
        
        import time
        
        # Test strategic cache performance
        self.stdout.write("\nTesting Strategic Cache Performance:")
        
        # Test organization data caching
        start_time = time.time()
        org_data = StrategicCacheManager.cache_organization_data(organization.id, force_refresh=True)
        cache_time = time.time() - start_time
        self.stdout.write(f"  - Organization data cache (fresh): {cache_time:.3f}s")
        
        start_time = time.time()
        org_data = StrategicCacheManager.get_organization_data(organization.id)
        hit_time = time.time() - start_time
        self.stdout.write(f"  - Organization data cache (hit): {hit_time:.3f}s")
        self.stdout.write(f"  - Cache speedup: {cache_time/hit_time:.1f}x faster")
        
        # Test deal statistics caching
        start_time = time.time()
        deal_stats = StrategicCacheManager.cache_deal_statistics(organization.id, days, force_refresh=True)
        cache_time = time.time() - start_time
        self.stdout.write(f"  - Deal statistics cache (fresh): {cache_time:.3f}s")
        
        start_time = time.time()
        deal_stats = StrategicCacheManager.get_deal_statistics(organization.id, days)
        hit_time = time.time() - start_time
        self.stdout.write(f"  - Deal statistics cache (hit): {hit_time:.3f}s")
        self.stdout.write(f"  - Cache speedup: {cache_time/hit_time:.1f}x faster")
        
        # Test API response caching
        self.stdout.write("\nTesting API Response Cache Performance:")
        
        # Get a test user
        from apps.authentication.models import User
        test_user = User.objects.filter(organization=organization, is_active=True).first()
        
        if test_user:
            start_time = time.time()
            dashboard_data = APIResponseOptimizer.cache_user_dashboard_data(
                test_user.id, organization.id, force_refresh=True
            )
            cache_time = time.time() - start_time
            self.stdout.write(f"  - Dashboard data cache (fresh): {cache_time:.3f}s")
            
            start_time = time.time()
            dashboard_data = APIResponseOptimizer.cache_user_dashboard_data(
                test_user.id, organization.id, force_refresh=False
            )
            hit_time = time.time() - start_time
            self.stdout.write(f"  - Dashboard data cache (hit): {hit_time:.3f}s")
            self.stdout.write(f"  - Cache speedup: {cache_time/hit_time:.1f}x faster")
        else:
            self.stdout.write("  - No test user found for dashboard cache testing")
        
        # Test cache warming
        self.stdout.write("\nTesting Cache Warming:")
        start_time = time.time()
        StrategicCacheManager.warm_organization_cache(organization.id)
        warm_time = time.time() - start_time
        self.stdout.write(f"  - Strategic cache warming: {warm_time:.3f}s")
        
        start_time = time.time()
        APIResponseOptimizer.warm_frequently_accessed_caches(organization.id)
        api_warm_time = time.time() - start_time
        self.stdout.write(f"  - API cache warming: {api_warm_time:.3f}s")
        
        self.stdout.write(f"\nCache performance testing completed")
        self.stdout.write(f"Total test time: {time.time() - start_time:.3f}s")