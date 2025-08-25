"""
Strategic Cache Manager
Implements Redis caching for frequently accessed organization data, user permissions, and deal statistics
"""

from django.core.cache import cache
from django.core.cache.utils import make_template_fragment_key
from django.utils import timezone
from django.db.models import Count, Sum, Avg, Q
from django.conf import settings
from datetime import timedelta, datetime
from typing import Dict, List, Optional, Any, Union
import json
import logging
import hashlib

# Performance logger
performance_logger = logging.getLogger('performance')

class StrategicCacheManager:
    """
    Centralized cache manager for strategic caching across the application
    """
    
    # Cache key prefixes
    ORGANIZATION_PREFIX = "org"
    USER_PERMISSIONS_PREFIX = "user_perms"
    DEAL_STATS_PREFIX = "deal_stats"
    ROLE_INFO_PREFIX = "role_info"
    DASHBOARD_PREFIX = "dashboard"
    
    # Cache TTL settings (in seconds)
    ORGANIZATION_TTL = 3600  # 1 hour
    USER_PERMISSIONS_TTL = 1800  # 30 minutes
    DEAL_STATS_TTL = 900  # 15 minutes
    ROLE_INFO_TTL = 3600  # 1 hour
    DASHBOARD_TTL = 600  # 10 minutes
    
    # Cache version for invalidation
    CACHE_VERSION = "v1"
    
    @classmethod
    def _make_key(cls, prefix: str, *args) -> str:
        """Create a standardized cache key"""
        key_parts = [cls.CACHE_VERSION, prefix] + [str(arg) for arg in args]
        return ":".join(key_parts)
    
    @classmethod
    def _hash_key(cls, key: str) -> str:
        """Create a hashed version of the key for very long keys"""
        if len(key) > 200:  # Redis key length limit consideration
            return hashlib.md5(key.encode()).hexdigest()
        return key
    
    # Organization Data Caching
    @classmethod
    def cache_organization_data(cls, organization_id: int, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Cache frequently accessed organization data
        """
        cache_key = cls._make_key(cls.ORGANIZATION_PREFIX, "data", organization_id)
        
        if not force_refresh:
            cached_data = cache.get(cache_key)
            if cached_data:
                performance_logger.debug(f"Cache hit for organization data: {organization_id}")
                return cached_data
        
        try:
            from organization.models import Organization
            from apps.authentication.models import User
            from deals.models import Deal
            
            organization = Organization.objects.get(id=organization_id)
            
            # Collect organization statistics
            org_data = {
                'id': organization.id,
                'name': organization.name,
                'is_active': organization.is_active,
                'created_at': organization.created_at.isoformat(),
                'statistics': {
                    'total_users': User.objects.filter(organization=organization).count(),
                    'active_users': User.objects.filter(organization=organization, is_active=True).count(),
                    'total_deals': Deal.objects.filter(organization=organization).count(),
                    'verified_deals': Deal.objects.filter(
                        organization=organization, 
                        verification_status='verified'
                    ).count(),
                    'total_deal_value': Deal.objects.filter(
                        organization=organization
                    ).aggregate(total=Sum('deal_value'))['total'] or 0,
                },
                'cached_at': timezone.now().isoformat()
            }
            
            # Cache the data
            cache.set(cache_key, org_data, cls.ORGANIZATION_TTL)
            performance_logger.info(f"Cached organization data for org {organization_id}")
            
            return org_data
            
        except Exception as e:
            performance_logger.error(f"Failed to cache organization data for {organization_id}: {str(e)}")
            return {}
    
    @classmethod
    def get_organization_data(cls, organization_id: int) -> Optional[Dict[str, Any]]:
        """Get cached organization data"""
        return cls.cache_organization_data(organization_id, force_refresh=False)
    
    @classmethod
    def invalidate_organization_cache(cls, organization_id: int):
        """Invalidate organization cache"""
        cache_key = cls._make_key(cls.ORGANIZATION_PREFIX, "data", organization_id)
        cache.delete(cache_key)
        performance_logger.info(f"Invalidated organization cache for org {organization_id}")
    
    # User Permissions and Role Caching
    @classmethod
    def cache_user_permissions(cls, user_id: int, organization_id: int, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Cache user permissions and role information per organization
        """
        cache_key = cls._make_key(cls.USER_PERMISSIONS_PREFIX, user_id, organization_id)
        
        if not force_refresh:
            cached_perms = cache.get(cache_key)
            if cached_perms:
                performance_logger.debug(f"Cache hit for user permissions: {user_id}")
                return cached_perms
        
        try:
            from apps.authentication.models import User
            from permissions.models import Role, Permission
            
            user = User.objects.select_related('role', 'organization').get(
                id=user_id, 
                organization_id=organization_id
            )
            
            # Collect user permission data
            permissions_data = {
                'user_id': user.id,
                'organization_id': organization_id,
                'role': {
                    'id': user.role.id if user.role else None,
                    'name': user.role.name if user.role else None,
                    'permissions': []
                },
                'is_active': user.is_active,
                'is_superuser': user.is_superuser,
                'cached_at': timezone.now().isoformat()
            }
            
            # Get role permissions
            if user.role:
                permissions = user.role.permissions.all()
                permissions_data['role']['permissions'] = [
                    {
                        'id': perm.id,
                        'codename': perm.codename,
                        'name': perm.name,
                        'content_type': perm.content_type.model if perm.content_type else None
                    }
                    for perm in permissions
                ]
            
            # Cache the permissions
            cache.set(cache_key, permissions_data, cls.USER_PERMISSIONS_TTL)
            performance_logger.info(f"Cached user permissions for user {user_id}")
            
            return permissions_data
            
        except Exception as e:
            performance_logger.error(f"Failed to cache user permissions for {user_id}: {str(e)}")
            return {}
    
    @classmethod
    def get_user_permissions(cls, user_id: int, organization_id: int) -> Optional[Dict[str, Any]]:
        """Get cached user permissions"""
        return cls.cache_user_permissions(user_id, organization_id, force_refresh=False)
    
    @classmethod
    def invalidate_user_permissions_cache(cls, user_id: int, organization_id: int):
        """Invalidate user permissions cache"""
        cache_key = cls._make_key(cls.USER_PERMISSIONS_PREFIX, user_id, organization_id)
        cache.delete(cache_key)
        performance_logger.info(f"Invalidated user permissions cache for user {user_id}")
    
    @classmethod
    def invalidate_organization_users_cache(cls, organization_id: int):
        """Invalidate all user caches for an organization"""
        try:
            from apps.authentication.models import User
            
            users = User.objects.filter(organization_id=organization_id).values_list('id', flat=True)
            for user_id in users:
                cls.invalidate_user_permissions_cache(user_id, organization_id)
            
            performance_logger.info(f"Invalidated all user caches for organization {organization_id}")
            
        except Exception as e:
            performance_logger.error(f"Failed to invalidate organization users cache: {str(e)}")
    
    # Role Information Caching
    @classmethod
    def cache_role_information(cls, organization_id: int, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Cache role information for organization
        """
        cache_key = cls._make_key(cls.ROLE_INFO_PREFIX, organization_id)
        
        if not force_refresh:
            cached_roles = cache.get(cache_key)
            if cached_roles:
                performance_logger.debug(f"Cache hit for role information: {organization_id}")
                return cached_roles
        
        try:
            from permissions.models import Role
            from apps.authentication.models import User
            
            roles = Role.objects.filter(organization_id=organization_id).prefetch_related('permissions')
            
            roles_data = {
                'organization_id': organization_id,
                'roles': [],
                'role_statistics': {},
                'cached_at': timezone.now().isoformat()
            }
            
            for role in roles:
                role_info = {
                    'id': role.id,
                    'name': role.name,
                    'description': getattr(role, 'description', ''),
                    'permissions_count': role.permissions.count(),
                    'permissions': [
                        {
                            'codename': perm.codename,
                            'name': perm.name
                        }
                        for perm in role.permissions.all()
                    ],
                    'user_count': User.objects.filter(role=role, is_active=True).count()
                }
                roles_data['roles'].append(role_info)
                
                # Role statistics
                roles_data['role_statistics'][role.name] = {
                    'user_count': role_info['user_count'],
                    'permissions_count': role_info['permissions_count']
                }
            
            # Cache the role data
            cache.set(cache_key, roles_data, cls.ROLE_INFO_TTL)
            performance_logger.info(f"Cached role information for organization {organization_id}")
            
            return roles_data
            
        except Exception as e:
            performance_logger.error(f"Failed to cache role information for {organization_id}: {str(e)}")
            return {}
    
    @classmethod
    def get_role_information(cls, organization_id: int) -> Optional[Dict[str, Any]]:
        """Get cached role information"""
        return cls.cache_role_information(organization_id, force_refresh=False)
    
    @classmethod
    def invalidate_role_cache(cls, organization_id: int):
        """Invalidate role cache for organization"""
        cache_key = cls._make_key(cls.ROLE_INFO_PREFIX, organization_id)
        cache.delete(cache_key)
        performance_logger.info(f"Invalidated role cache for organization {organization_id}")
    
    # Deal Statistics Caching
    @classmethod
    def cache_deal_statistics(cls, organization_id: int, days: int = 30, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Cache deal statistics and reporting data
        """
        cache_key = cls._make_key(cls.DEAL_STATS_PREFIX, organization_id, days)
        
        if not force_refresh:
            cached_stats = cache.get(cache_key)
            if cached_stats:
                performance_logger.debug(f"Cache hit for deal statistics: {organization_id}")
                return cached_stats
        
        try:
            from deals.models import Deal, Payment
            from django.db.models.functions import TruncDate
            
            # Date range for statistics
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)
            
            base_query = Deal.objects.filter(
                organization_id=organization_id,
                created_at__gte=start_date
            )
            
            # Basic statistics
            deal_stats = base_query.aggregate(
                total_deals=Count('id'),
                verified_deals=Count('id', filter=Q(verification_status='verified')),
                pending_deals=Count('id', filter=Q(verification_status='pending')),
                rejected_deals=Count('id', filter=Q(verification_status='rejected')),
                total_value=Sum('deal_value'),
                avg_deal_value=Avg('deal_value'),
                full_payment_deals=Count('id', filter=Q(payment_status='full_payment')),
                partial_payment_deals=Count('id', filter=Q(payment_status='partial_payment'))
            )
            
            # Daily trends
            daily_trends = base_query.annotate(
                date=TruncDate('created_at')
            ).values('date').annotate(
                count=Count('id'),
                total_value=Sum('deal_value')
            ).order_by('date')
            
            # Source type distribution
            source_distribution = base_query.values('source_type').annotate(
                count=Count('id'),
                total_value=Sum('deal_value')
            ).order_by('-count')
            
            # Payment method distribution
            payment_method_distribution = base_query.values('payment_method').annotate(
                count=Count('id'),
                total_value=Sum('deal_value')
            ).order_by('-count')
            
            # Top clients by deal count
            top_clients = base_query.values(
                'client__client_name'
            ).annotate(
                deal_count=Count('id'),
                total_value=Sum('deal_value')
            ).order_by('-deal_count')[:10]
            
            statistics_data = {
                'organization_id': organization_id,
                'period_days': days,
                'basic_stats': deal_stats,
                'daily_trends': list(daily_trends),
                'source_distribution': list(source_distribution),
                'payment_method_distribution': list(payment_method_distribution),
                'top_clients': list(top_clients),
                'cached_at': timezone.now().isoformat()
            }
            
            # Cache the statistics
            cache.set(cache_key, statistics_data, cls.DEAL_STATS_TTL)
            performance_logger.info(f"Cached deal statistics for organization {organization_id}")
            
            return statistics_data
            
        except Exception as e:
            performance_logger.error(f"Failed to cache deal statistics for {organization_id}: {str(e)}")
            return {}
    
    @classmethod
    def get_deal_statistics(cls, organization_id: int, days: int = 30) -> Optional[Dict[str, Any]]:
        """Get cached deal statistics"""
        return cls.cache_deal_statistics(organization_id, days, force_refresh=False)
    
    @classmethod
    def invalidate_deal_statistics_cache(cls, organization_id: int):
        """Invalidate deal statistics cache for organization"""
        # Invalidate all deal stats caches for different day ranges
        for days in [7, 30, 90, 365]:
            cache_key = cls._make_key(cls.DEAL_STATS_PREFIX, organization_id, days)
            cache.delete(cache_key)
        
        performance_logger.info(f"Invalidated deal statistics cache for organization {organization_id}")
    
    # Dashboard Data Caching
    @classmethod
    def cache_dashboard_data(cls, user_id: int, organization_id: int, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Cache user dashboard data and statistics
        """
        cache_key = cls._make_key(cls.DASHBOARD_PREFIX, user_id, organization_id)
        
        if not force_refresh:
            cached_dashboard = cache.get(cache_key)
            if cached_dashboard:
                performance_logger.debug(f"Cache hit for dashboard data: {user_id}")
                return cached_dashboard
        
        try:
            # Get organization data
            org_data = cls.get_organization_data(organization_id)
            
            # Get user permissions
            user_perms = cls.get_user_permissions(user_id, organization_id)
            
            # Get deal statistics
            deal_stats = cls.get_deal_statistics(organization_id, days=30)
            
            # Get role information
            role_info = cls.get_role_information(organization_id)
            
            dashboard_data = {
                'user_id': user_id,
                'organization_id': organization_id,
                'organization_data': org_data,
                'user_permissions': user_perms,
                'deal_statistics': deal_stats,
                'role_information': role_info,
                'cached_at': timezone.now().isoformat()
            }
            
            # Cache the dashboard data
            cache.set(cache_key, dashboard_data, cls.DASHBOARD_TTL)
            performance_logger.info(f"Cached dashboard data for user {user_id}")
            
            return dashboard_data
            
        except Exception as e:
            performance_logger.error(f"Failed to cache dashboard data for user {user_id}: {str(e)}")
            return {}
    
    @classmethod
    def get_dashboard_data(cls, user_id: int, organization_id: int) -> Optional[Dict[str, Any]]:
        """Get cached dashboard data"""
        return cls.cache_dashboard_data(user_id, organization_id, force_refresh=False)
    
    @classmethod
    def invalidate_dashboard_cache(cls, user_id: int, organization_id: int):
        """Invalidate dashboard cache for user"""
        cache_key = cls._make_key(cls.DASHBOARD_PREFIX, user_id, organization_id)
        cache.delete(cache_key)
        performance_logger.info(f"Invalidated dashboard cache for user {user_id}")
    
    # Cache Warming
    @classmethod
    def warm_organization_cache(cls, organization_id: int):
        """
        Warm up cache for frequently accessed organization data
        """
        try:
            performance_logger.info(f"Starting cache warming for organization {organization_id}")
            
            # Warm organization data
            cls.cache_organization_data(organization_id, force_refresh=True)
            
            # Warm role information
            cls.cache_role_information(organization_id, force_refresh=True)
            
            # Warm deal statistics for common periods
            for days in [7, 30, 90]:
                cls.cache_deal_statistics(organization_id, days, force_refresh=True)
            
            # Warm user permissions for active users
            from apps.authentication.models import User
            active_users = User.objects.filter(
                organization_id=organization_id,
                is_active=True
            ).values_list('id', flat=True)[:50]  # Limit to 50 most recent active users
            
            for user_id in active_users:
                cls.cache_user_permissions(user_id, organization_id, force_refresh=True)
            
            performance_logger.info(f"Cache warming completed for organization {organization_id}")
            
        except Exception as e:
            performance_logger.error(f"Cache warming failed for organization {organization_id}: {str(e)}")
    
    # Cache Invalidation Helpers
    @classmethod
    def invalidate_organization_related_caches(cls, organization_id: int):
        """
        Invalidate all caches related to an organization
        """
        try:
            # Invalidate organization data
            cls.invalidate_organization_cache(organization_id)
            
            # Invalidate role cache
            cls.invalidate_role_cache(organization_id)
            
            # Invalidate deal statistics
            cls.invalidate_deal_statistics_cache(organization_id)
            
            # Invalidate user permissions for all users in organization
            cls.invalidate_organization_users_cache(organization_id)
            
            # Invalidate dashboard caches for all users in organization
            from apps.authentication.models import User
            users = User.objects.filter(organization_id=organization_id).values_list('id', flat=True)
            for user_id in users:
                cls.invalidate_dashboard_cache(user_id, organization_id)
            
            performance_logger.info(f"Invalidated all caches for organization {organization_id}")
            
        except Exception as e:
            performance_logger.error(f"Failed to invalidate organization caches: {str(e)}")
    
    @classmethod
    def invalidate_user_related_caches(cls, user_id: int, organization_id: int):
        """
        Invalidate all caches related to a user
        """
        try:
            # Invalidate user permissions
            cls.invalidate_user_permissions_cache(user_id, organization_id)
            
            # Invalidate dashboard cache
            cls.invalidate_dashboard_cache(user_id, organization_id)
            
            performance_logger.info(f"Invalidated all caches for user {user_id}")
            
        except Exception as e:
            performance_logger.error(f"Failed to invalidate user caches: {str(e)}")
    
    # Cache Statistics and Monitoring
    @classmethod
    def get_cache_statistics(cls) -> Dict[str, Any]:
        """
        Get cache usage statistics
        """
        try:
            from django.core.cache import cache
            
            # This would depend on your Redis configuration
            # For now, return basic info
            stats = {
                'cache_backend': str(cache.__class__),
                'timestamp': timezone.now().isoformat(),
                'cache_prefixes': {
                    'organization': cls.ORGANIZATION_PREFIX,
                    'user_permissions': cls.USER_PERMISSIONS_PREFIX,
                    'deal_stats': cls.DEAL_STATS_PREFIX,
                    'role_info': cls.ROLE_INFO_PREFIX,
                    'dashboard': cls.DASHBOARD_PREFIX
                },
                'ttl_settings': {
                    'organization': cls.ORGANIZATION_TTL,
                    'user_permissions': cls.USER_PERMISSIONS_TTL,
                    'deal_stats': cls.DEAL_STATS_TTL,
                    'role_info': cls.ROLE_INFO_TTL,
                    'dashboard': cls.DASHBOARD_TTL
                }
            }
            
            return stats
            
        except Exception as e:
            performance_logger.error(f"Failed to get cache statistics: {str(e)}")
            return {}
    
    @classmethod
    def clear_all_strategic_caches(cls):
        """
        Clear all strategic caches (use with caution)
        """
        try:
            # This would clear all caches with our prefixes
            # Implementation depends on your Redis setup
            performance_logger.warning("Clearing all strategic caches")
            
            # For Django cache, we'd need to iterate through known keys
            # This is a simplified version
            cache.clear()
            
            performance_logger.info("All strategic caches cleared")
            
        except Exception as e:
            performance_logger.error(f"Failed to clear strategic caches: {str(e)}")


# Cache invalidation signals
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

@receiver(post_save, sender='organization.Organization')
def invalidate_organization_cache_on_save(sender, instance, **kwargs):
    """Invalidate organization cache when organization is updated"""
    StrategicCacheManager.invalidate_organization_related_caches(instance.id)

@receiver(post_save, sender='authentication.User')
def invalidate_user_cache_on_save(sender, instance, **kwargs):
    """Invalidate user cache when user is updated"""
    if instance.organization:
        StrategicCacheManager.invalidate_user_related_caches(instance.id, instance.organization.id)

@receiver(post_save, sender='deals.Deal')
def invalidate_deal_cache_on_save(sender, instance, **kwargs):
    """Invalidate deal statistics cache when deal is updated"""
    StrategicCacheManager.invalidate_deal_statistics_cache(instance.organization.id)

@receiver(post_save, sender='permissions.Role')
def invalidate_role_cache_on_save(sender, instance, **kwargs):
    """Invalidate role cache when role is updated"""
    # Handle global superadmin roles that don't have an organization
    if instance.organization is not None:
        StrategicCacheManager.invalidate_role_cache(instance.organization.id)
        StrategicCacheManager.invalidate_organization_users_cache(instance.organization.id)