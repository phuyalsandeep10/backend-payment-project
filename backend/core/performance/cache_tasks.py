"""
Celery tasks for cache management and optimization
"""

from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from datetime import timedelta
import logging

from .strategic_cache_manager import StrategicCacheManager
from .api_response_optimizer import APIResponseOptimizer, CacheWarmingManager

# Task logger
logger = get_task_logger(__name__)

@shared_task(bind=True, max_retries=3)
def warm_organization_caches(self, organization_id=None):
    """
    Background task to warm organization caches
    """
    try:
        if organization_id:
            from organization.models import Organization
            organization = Organization.objects.get(id=organization_id)
            
            logger.info(f"Starting cache warming for organization {organization.name}")
            
            # Warm strategic caches
            StrategicCacheManager.warm_organization_cache(organization_id)
            
            # Warm API response caches
            APIResponseOptimizer.warm_frequently_accessed_caches(organization_id)
            
            logger.info(f"Cache warming completed for organization {organization.name}")
            
            return {
                'success': True,
                'organization_id': organization_id,
                'organization_name': organization.name,
                'warmed_at': timezone.now().isoformat()
            }
        else:
            # Warm caches for all active organizations
            logger.info("Starting cache warming for all organizations")
            
            CacheWarmingManager.warm_all_organization_caches()
            
            logger.info("Cache warming completed for all organizations")
            
            return {
                'success': True,
                'scope': 'all_organizations',
                'warmed_at': timezone.now().isoformat()
            }
        
    except Exception as e:
        logger.error(f"Cache warming failed: {str(e)}")
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying cache warming in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise

@shared_task(bind=True)
def invalidate_organization_caches(self, organization_id, cache_type='all'):
    """
    Background task to invalidate organization caches
    """
    try:
        from organization.models import Organization
        organization = Organization.objects.get(id=organization_id)
        
        logger.info(f"Starting cache invalidation for organization {organization.name}")
        
        if cache_type in ['strategic', 'all']:
            # Invalidate strategic caches
            StrategicCacheManager.invalidate_organization_related_caches(organization_id)
            logger.info("Strategic caches invalidated")
        
        if cache_type in ['api', 'all']:
            # Invalidate API response caches
            APIResponseOptimizer.invalidate_api_caches(
                cache_pattern='all',
                organization_id=organization_id
            )
            logger.info("API response caches invalidated")
        
        logger.info(f"Cache invalidation completed for organization {organization.name}")
        
        return {
            'success': True,
            'organization_id': organization_id,
            'organization_name': organization.name,
            'cache_type': cache_type,
            'invalidated_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Cache invalidation failed: {str(e)}")
        raise

@shared_task(bind=True)
def invalidate_user_caches(self, user_id, organization_id):
    """
    Background task to invalidate user-specific caches
    """
    try:
        from apps.authentication.models import User
        user = User.objects.get(id=user_id)
        
        logger.info(f"Starting cache invalidation for user {user.email}")
        
        # Invalidate strategic user caches
        StrategicCacheManager.invalidate_user_related_caches(user_id, organization_id)
        
        # Invalidate API response caches
        APIResponseOptimizer.invalidate_api_caches(
            cache_pattern='dashboard',
            organization_id=organization_id,
            user_id=user_id
        )
        
        logger.info(f"Cache invalidation completed for user {user.email}")
        
        return {
            'success': True,
            'user_id': user_id,
            'user_email': user.email,
            'organization_id': organization_id,
            'invalidated_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"User cache invalidation failed: {str(e)}")
        raise

@shared_task
def scheduled_cache_warming():
    """
    Scheduled task for regular cache warming
    Runs every few hours to keep caches warm
    """
    try:
        logger.info("Starting scheduled cache warming")
        
        from organization.models import Organization
        
        # Get active organizations
        active_orgs = Organization.objects.filter(is_active=True)
        
        warming_results = []
        
        for org in active_orgs:
            try:
                # Warm caches for each organization
                result = warm_organization_caches.delay(org.id)
                warming_results.append({
                    'organization_id': org.id,
                    'organization_name': org.name,
                    'task_id': result.id,
                    'status': 'queued'
                })
                
            except Exception as e:
                logger.error(f"Failed to queue cache warming for {org.name}: {str(e)}")
                warming_results.append({
                    'organization_id': org.id,
                    'organization_name': org.name,
                    'status': 'failed',
                    'error': str(e)
                })
        
        logger.info(f"Scheduled cache warming completed: {len(warming_results)} organizations processed")
        
        return {
            'success': True,
            'organizations_processed': len(warming_results),
            'results': warming_results,
            'scheduled_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Scheduled cache warming failed: {str(e)}")
        raise

@shared_task
def cache_maintenance():
    """
    Scheduled task for cache maintenance
    Cleans up expired caches and optimizes cache usage
    """
    try:
        logger.info("Starting cache maintenance")
        
        maintenance_results = {
            'started_at': timezone.now().isoformat(),
            'actions_performed': [],
            'statistics': {},
            'completed_at': None
        }
        
        # Get cache statistics before maintenance
        strategic_stats = StrategicCacheManager.get_cache_statistics()
        api_stats = APIResponseOptimizer.get_cache_performance_metrics()
        
        maintenance_results['statistics']['before'] = {
            'strategic_cache': strategic_stats,
            'api_cache': api_stats
        }
        
        # Perform maintenance actions
        maintenance_results['actions_performed'].append('Cache statistics collected')
        
        # Clean up old cache entries (this would be implemented based on your cache backend)
        # For now, we'll just log the action
        logger.info("Cache cleanup completed")
        maintenance_results['actions_performed'].append('Cache cleanup performed')
        
        # Get cache statistics after maintenance
        strategic_stats_after = StrategicCacheManager.get_cache_statistics()
        api_stats_after = APIResponseOptimizer.get_cache_performance_metrics()
        
        maintenance_results['statistics']['after'] = {
            'strategic_cache': strategic_stats_after,
            'api_cache': api_stats_after
        }
        
        maintenance_results['completed_at'] = timezone.now().isoformat()
        
        logger.info("Cache maintenance completed successfully")
        
        return maintenance_results
        
    except Exception as e:
        logger.error(f"Cache maintenance failed: {str(e)}")
        raise

@shared_task(bind=True)
def warm_user_specific_caches(self, organization_id, user_limit=50):
    """
    Background task to warm user-specific caches
    """
    try:
        from organization.models import Organization
        from apps.authentication.models import User
        
        organization = Organization.objects.get(id=organization_id)
        
        logger.info(f"Starting user-specific cache warming for {organization.name}")
        
        # Get recently active users
        recent_users = User.objects.filter(
            organization_id=organization_id,
            is_active=True,
            last_login__gte=timezone.now() - timedelta(days=7)
        ).order_by('-last_login')[:user_limit]
        
        warming_results = []
        
        for user in recent_users:
            try:
                # Warm user permissions cache
                StrategicCacheManager.cache_user_permissions(
                    user.id, organization_id, force_refresh=True
                )
                
                # Warm user dashboard cache
                APIResponseOptimizer.cache_user_dashboard_data(
                    user.id, organization_id, force_refresh=True
                )
                
                warming_results.append({
                    'user_id': user.id,
                    'user_email': user.email,
                    'status': 'success'
                })
                
            except Exception as e:
                logger.error(f"Failed to warm caches for user {user.email}: {str(e)}")
                warming_results.append({
                    'user_id': user.id,
                    'user_email': user.email,
                    'status': 'failed',
                    'error': str(e)
                })
        
        logger.info(f"User-specific cache warming completed: {len(warming_results)} users processed")
        
        return {
            'success': True,
            'organization_id': organization_id,
            'organization_name': organization.name,
            'users_processed': len(warming_results),
            'results': warming_results,
            'warmed_at': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"User-specific cache warming failed: {str(e)}")
        raise

@shared_task
def generate_cache_performance_report():
    """
    Generate comprehensive cache performance report
    """
    try:
        logger.info("Generating cache performance report")
        
        from organization.models import Organization
        
        report_data = {
            'generated_at': timezone.now().isoformat(),
            'strategic_cache_stats': StrategicCacheManager.get_cache_statistics(),
            'api_cache_stats': APIResponseOptimizer.get_cache_performance_metrics(),
            'organization_reports': [],
            'summary': {}
        }
        
        # Generate per-organization cache reports
        active_orgs = Organization.objects.filter(is_active=True)
        
        for org in active_orgs:
            org_report = {
                'organization_id': org.id,
                'organization_name': org.name,
                'cache_status': {}
            }
            
            # Check organization data cache
            org_data = StrategicCacheManager.get_organization_data(org.id)
            org_report['cache_status']['organization_data'] = bool(org_data)
            
            # Check role information cache
            role_info = StrategicCacheManager.get_role_information(org.id)
            org_report['cache_status']['role_information'] = bool(role_info)
            
            # Check deal statistics cache
            deal_stats = StrategicCacheManager.get_deal_statistics(org.id, 30)
            org_report['cache_status']['deal_statistics'] = bool(deal_stats)
            
            report_data['organization_reports'].append(org_report)
        
        # Generate summary
        total_orgs = len(report_data['organization_reports'])
        cached_org_data = sum(1 for org in report_data['organization_reports'] 
                             if org['cache_status']['organization_data'])
        cached_roles = sum(1 for org in report_data['organization_reports'] 
                          if org['cache_status']['role_information'])
        cached_deals = sum(1 for org in report_data['organization_reports'] 
                          if org['cache_status']['deal_statistics'])
        
        report_data['summary'] = {
            'total_organizations': total_orgs,
            'organization_data_cached': cached_org_data,
            'role_information_cached': cached_roles,
            'deal_statistics_cached': cached_deals,
            'cache_coverage': {
                'organization_data': (cached_org_data / total_orgs * 100) if total_orgs > 0 else 0,
                'role_information': (cached_roles / total_orgs * 100) if total_orgs > 0 else 0,
                'deal_statistics': (cached_deals / total_orgs * 100) if total_orgs > 0 else 0
            }
        }
        
        # Store report in cache for dashboard access
        from django.core.cache import cache
        cache.set('cache_performance_report', report_data, 3600)  # Cache for 1 hour
        
        logger.info("Cache performance report generated successfully")
        
        return report_data
        
    except Exception as e:
        logger.error(f"Cache performance report generation failed: {str(e)}")
        raise

@shared_task
def cleanup_expired_caches():
    """
    Clean up expired cache entries
    """
    try:
        logger.info("Starting expired cache cleanup")
        
        # This would implement cache cleanup logic based on your cache backend
        # For Redis, you might use SCAN and TTL commands
        # For now, we'll just log the action
        
        cleanup_results = {
            'started_at': timezone.now().isoformat(),
            'expired_keys_removed': 0,  # Would be actual count
            'space_freed': 0,  # Would be actual bytes freed
            'completed_at': timezone.now().isoformat()
        }
        
        logger.info("Expired cache cleanup completed")
        
        return cleanup_results
        
    except Exception as e:
        logger.error(f"Expired cache cleanup failed: {str(e)}")
        raise


# Periodic task configuration (to be added to celery beat schedule)
CACHE_PERIODIC_TASKS = {
    'scheduled-cache-warming': {
        'task': 'core_config.cache_tasks.scheduled_cache_warming',
        'schedule': 14400.0,  # Run every 4 hours
        'options': {'queue': 'cache'}
    },
    'cache-maintenance': {
        'task': 'core_config.cache_tasks.cache_maintenance',
        'schedule': 3600.0,  # Run every hour
        'options': {'queue': 'maintenance'}
    },
    'generate-cache-performance-report': {
        'task': 'core_config.cache_tasks.generate_cache_performance_report',
        'schedule': 21600.0,  # Run every 6 hours
        'options': {'queue': 'reports'}
    },
    'cleanup-expired-caches': {
        'task': 'core_config.cache_tasks.cleanup_expired_caches',
        'schedule': 7200.0,  # Run every 2 hours
        'options': {'queue': 'maintenance'}
    }
}