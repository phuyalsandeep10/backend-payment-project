"""
Role Permission Caching Service
Provides efficient caching for role permissions per organization
"""

from django.core.cache import cache
from django.db.models import Prefetch
from django.utils import timezone
from .models import Role, Permission
from apps.authentication.models import User
import logging

# Performance logger
performance_logger = logging.getLogger('performance')

class RolePermissionCache:
    """
    Service for caching role permissions to improve performance
    """
    
    # Cache timeout settings (in seconds)
    ROLE_PERMISSIONS_TIMEOUT = 1800  # 30 minutes
    USER_PERMISSIONS_TIMEOUT = 900   # 15 minutes
    ROLE_LIST_TIMEOUT = 600          # 10 minutes
    
    @classmethod
    def get_role_permissions(cls, role_id):
        """
        Get cached permissions for a specific role
        """
        cache_key = f"role_permissions_{role_id}"
        permissions = cache.get(cache_key)
        
        if permissions is None:
            try:
                role = Role.objects.prefetch_related('permissions').get(id=role_id)
                permissions = list(role.permissions.values('id', 'name', 'codename', 'content_type__app_label'))
                cache.set(cache_key, permissions, cls.ROLE_PERMISSIONS_TIMEOUT)
                performance_logger.info(f"Cached permissions for role {role.name} (ID: {role_id})")
            except Role.DoesNotExist:
                permissions = []
                cache.set(cache_key, permissions, cls.ROLE_PERMISSIONS_TIMEOUT)
        
        return permissions
    
    @classmethod
    def get_user_permissions(cls, user_id):
        """
        Get cached permissions for a specific user (through their role)
        """
        cache_key = f"user_permissions_{user_id}"
        permissions = cache.get(cache_key)
        
        if permissions is None:
            try:
                user = User.objects.select_related('role').get(id=user_id)
                if user.role:
                    permissions = cls.get_role_permissions(user.role.id)
                else:
                    permissions = []
                cache.set(cache_key, permissions, cls.USER_PERMISSIONS_TIMEOUT)
                performance_logger.info(f"Cached permissions for user {user.email} (ID: {user_id})")
            except User.DoesNotExist:
                permissions = []
                cache.set(cache_key, permissions, cls.USER_PERMISSIONS_TIMEOUT)
        
        return permissions
    
    @classmethod
    def get_organization_roles(cls, organization_id):
        """
        Get cached roles for an organization with their permissions
        """
        cache_key = f"org_roles_detailed_{organization_id}"
        roles = cache.get(cache_key)
        
        if roles is None:
            roles_queryset = Role.objects.filter(
                organization_id=organization_id
            ).prefetch_related(
                'permissions',
                Prefetch('users', queryset=User.objects.filter(is_active=True))
            )
            
            roles = []
            for role in roles_queryset:
                role_data = {
                    'id': role.id,
                    'name': role.name,
                    'permissions': list(role.permissions.values('id', 'name', 'codename')),
                    'user_count': role.users.count(),
                    'users': [
                        {
                            'id': user.id,
                            'email': user.email,
                            'name': user.get_full_name() or user.username
                        }
                        for user in role.users.all()
                    ]
                }
                roles.append(role_data)
            
            cache.set(cache_key, roles, cls.ROLE_LIST_TIMEOUT)
            performance_logger.info(f"Cached detailed roles for organization {organization_id}")
        
        return roles
    
    @classmethod
    def user_has_permission(cls, user_id, permission_codename):
        """
        Check if user has a specific permission (cached)
        """
        permissions = cls.get_user_permissions(user_id)
        return any(perm['codename'] == permission_codename for perm in permissions)
    
    @classmethod
    def user_has_any_permission(cls, user_id, permission_codenames):
        """
        Check if user has any of the specified permissions (cached)
        """
        permissions = cls.get_user_permissions(user_id)
        user_codenames = {perm['codename'] for perm in permissions}
        return bool(user_codenames.intersection(set(permission_codenames)))
    
    @classmethod
    def invalidate_role_cache(cls, role_id):
        """
        Invalidate cache for a specific role
        """
        cache_keys = [
            f"role_permissions_{role_id}",
        ]
        
        # Also invalidate user caches for users with this role
        try:
            role = Role.objects.get(id=role_id)
            user_ids = role.users.values_list('id', flat=True)
            for user_id in user_ids:
                cache_keys.append(f"user_permissions_{user_id}")
            
            # Invalidate organization cache
            if role.organization:
                cache_keys.append(f"org_roles_detailed_{role.organization.id}")
        except Role.DoesNotExist:
            pass
        
        for key in cache_keys:
            cache.delete(key)
        
        performance_logger.info(f"Invalidated cache for role {role_id}")
    
    @classmethod
    def invalidate_user_cache(cls, user_id):
        """
        Invalidate cache for a specific user
        """
        cache_key = f"user_permissions_{user_id}"
        cache.delete(cache_key)
        performance_logger.info(f"Invalidated cache for user {user_id}")
    
    @classmethod
    def invalidate_organization_cache(cls, organization_id):
        """
        Invalidate all caches for an organization
        """
        cache_keys = [
            f"org_roles_{organization_id}",
            f"org_roles_detailed_{organization_id}",
            f"role_analytics_{organization_id}",
        ]
        
        # Get all roles in the organization and invalidate their caches
        try:
            role_ids = Role.objects.filter(organization_id=organization_id).values_list('id', flat=True)
            for role_id in role_ids:
                cache_keys.append(f"role_permissions_{role_id}")
            
            # Get all users in the organization and invalidate their caches
            user_ids = User.objects.filter(organization_id=organization_id).values_list('id', flat=True)
            for user_id in user_ids:
                cache_keys.append(f"user_permissions_{user_id}")
        except Exception as e:
            performance_logger.error(f"Error getting organization data for cache invalidation: {e}")
        
        for key in cache_keys:
            cache.delete(key)
        
        performance_logger.info(f"Invalidated all caches for organization {organization_id}")
    
    @classmethod
    def warm_organization_cache(cls, organization_id):
        """
        Pre-warm caches for an organization
        """
        performance_logger.info(f"Warming cache for organization {organization_id}")
        
        # Warm role caches
        roles = cls.get_organization_roles(organization_id)
        
        # Warm user permission caches
        user_ids = User.objects.filter(
            organization_id=organization_id,
            is_active=True
        ).values_list('id', flat=True)
        
        for user_id in user_ids:
            cls.get_user_permissions(user_id)
        
        performance_logger.info(f"Cache warming completed for organization {organization_id}")
    
    @classmethod
    def get_cache_stats(cls, organization_id):
        """
        Get cache statistics for an organization
        """
        stats = {
            'organization_id': organization_id,
            'timestamp': timezone.now().isoformat(),
            'cached_items': {
                'roles': 0,
                'users': 0,
                'permissions': 0
            }
        }
        
        # Count cached roles
        role_ids = Role.objects.filter(organization_id=organization_id).values_list('id', flat=True)
        for role_id in role_ids:
            if cache.get(f"role_permissions_{role_id}") is not None:
                stats['cached_items']['roles'] += 1
        
        # Count cached users
        user_ids = User.objects.filter(organization_id=organization_id).values_list('id', flat=True)
        for user_id in user_ids:
            if cache.get(f"user_permissions_{user_id}") is not None:
                stats['cached_items']['users'] += 1
        
        # Check organization cache
        if cache.get(f"org_roles_detailed_{organization_id}") is not None:
            stats['cached_items']['permissions'] = 1
        
        return stats


# Utility functions for easy access
def get_user_permissions(user_id):
    """Convenience function to get user permissions"""
    return RolePermissionCache.get_user_permissions(user_id)

def user_has_permission(user_id, permission_codename):
    """Convenience function to check user permission"""
    return RolePermissionCache.user_has_permission(user_id, permission_codename)

def invalidate_user_cache(user_id):
    """Convenience function to invalidate user cache"""
    return RolePermissionCache.invalidate_user_cache(user_id)