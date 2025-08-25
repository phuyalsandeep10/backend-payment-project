"""
Signal handlers for role and permission cache management
"""

from django.db.models.signals import post_save, post_delete, m2m_changed
from django.dispatch import receiver
from .models import Role
from apps.authentication.models import User
from .cache_service import RolePermissionCache
import logging

# Performance logger
performance_logger = logging.getLogger('performance')

@receiver(post_save, sender=Role)
def role_saved_handler(sender, instance, created, **kwargs):
    """
    Handle role save events - invalidate related caches
    """
    performance_logger.info(f"Role {'created' if created else 'updated'}: {instance.name}")
    
    # Invalidate role cache
    RolePermissionCache.invalidate_role_cache(instance.id)
    
    # If role belongs to an organization, invalidate organization cache
    if instance.organization:
        RolePermissionCache.invalidate_organization_cache(instance.organization.id)

@receiver(post_delete, sender=Role)
def role_deleted_handler(sender, instance, **kwargs):
    """
    Handle role deletion - invalidate related caches
    """
    performance_logger.info(f"Role deleted: {instance.name}")
    
    # Invalidate role cache
    RolePermissionCache.invalidate_role_cache(instance.id)
    
    # If role belonged to an organization, invalidate organization cache
    if instance.organization:
        RolePermissionCache.invalidate_organization_cache(instance.organization.id)

@receiver(m2m_changed, sender=Role.permissions.through)
def role_permissions_changed_handler(sender, instance, action, pk_set, **kwargs):
    """
    Handle changes to role permissions - invalidate related caches
    """
    if action in ['post_add', 'post_remove', 'post_clear']:
        performance_logger.info(f"Role permissions {action} for role: {instance.name}")
        
        # Invalidate role cache
        RolePermissionCache.invalidate_role_cache(instance.id)
        
        # If role belongs to an organization, invalidate organization cache
        if instance.organization:
            RolePermissionCache.invalidate_organization_cache(instance.organization.id)

@receiver(post_save, sender=User)
def user_role_changed_handler(sender, instance, created, **kwargs):
    """
    Handle user role changes - invalidate user permission cache
    """
    if not created:  # Only for updates, not new user creation
        # Check if role was changed
        if hasattr(instance, '_original_role_id'):
            if instance._original_role_id != (instance.role.id if instance.role else None):
                performance_logger.info(f"User role changed for: {instance.email}")
                
                # Invalidate user cache
                RolePermissionCache.invalidate_user_cache(instance.id)
                
                # If user belongs to an organization, invalidate organization cache
                if instance.organization:
                    RolePermissionCache.invalidate_organization_cache(instance.organization.id)

# Custom signal to track role changes
def track_user_role_changes():
    """
    Monkey patch User model to track role changes
    """
    original_init = User.__init__
    
    def new_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        if self.pk:
            self._original_role_id = self.role.id if self.role else None
    
    User.__init__ = new_init

# Initialize role change tracking
track_user_role_changes()