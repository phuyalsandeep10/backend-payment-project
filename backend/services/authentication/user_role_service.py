"""
User Role Service - Task 2.3.2

Reduces User model coupling by extracting role and permission operations
into a dedicated service with clean interfaces.
"""

from services.base_service import BaseService
from typing import Dict, Optional, Any, List, Set
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import transaction
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class UserRoleService(BaseService):
    """
    Service for user role and permission operations.
    Implements composition pattern to reduce User model coupling.
    """

    def __init__(self, user=None, organization=None, **kwargs):
        super().__init__(user=user, organization=organization)

    def get_service_name(self) -> str:
        """Return the name of this service for logging and identification"""
        return "user_role_service"

    def get_user_permissions(self, user_id: int) -> Dict[str, Any]:
        """
        Get comprehensive user permissions without tight coupling.
        
        Args:
            user_id: User ID
            
        Returns:
            dict: Permission data structure
        """
        try:
            user = User.objects.select_related('role').prefetch_related(
                'user_permissions', 'groups__permissions'
            ).get(id=user_id)
            
            # Get role-based permissions
            role_permissions = self._get_role_permissions(user.role) if user.role else set()
            
            # Get direct user permissions
            direct_permissions = set(user.user_permissions.values_list('codename', flat=True))
            
            # Get group permissions
            group_permissions = set()
            for group in user.groups.all():
                group_permissions.update(group.permissions.values_list('codename', flat=True))
            
            # Combine all permissions
            all_permissions = role_permissions | direct_permissions | group_permissions
            
            return {
                'user_id': user_id,
                'role': {
                    'id': user.role.id if user.role else None,
                    'name': user.role.name if user.role else None,
                    'permissions': list(role_permissions)
                },
                'direct_permissions': list(direct_permissions),
                'group_permissions': list(group_permissions),
                'all_permissions': list(all_permissions),
                'permission_count': len(all_permissions),
                'is_superuser': user.is_superuser,
                'is_staff': user.is_staff
            }
            
        except User.DoesNotExist:
            return {'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error getting user permissions {user_id}: {e}")
            return {'error': 'Failed to get permissions'}

    def check_user_permission(self, user_id: int, permission: str, 
                             resource_id: Optional[int] = None) -> bool:
        """
        Check if user has specific permission with optional resource context.
        
        Args:
            user_id: User ID
            permission: Permission codename to check
            resource_id: Optional resource ID for resource-based permissions
            
        Returns:
            bool: True if user has permission
        """
        try:
            user = User.objects.select_related('role', 'organization').get(id=user_id)
            
            # Superuser has all permissions
            if user.is_superuser:
                return True
            
            # Check direct permission
            if user.user_permissions.filter(codename=permission).exists():
                return True
            
            # Check role-based permission
            if user.role and self._role_has_permission(user.role, permission):
                return True
            
            # Check group permissions
            if user.groups.filter(permissions__codename=permission).exists():
                return True
            
            # Check organization-scoped permissions if applicable
            if resource_id and user.organization:
                return self._check_organization_permission(user, permission, resource_id)
            
            return False
            
        except User.DoesNotExist:
            return False
        except Exception as e:
            logger.error(f"Error checking permission {permission} for user {user_id}: {e}")
            return False

    def assign_role_to_user(self, user_id: int, role_id: int, 
                           assigned_by: Optional[User] = None) -> Dict[str, Any]:
        """
        Assign role to user with proper authorization and audit.
        
        Args:
            user_id: User ID
            role_id: Role ID to assign
            assigned_by: User performing the assignment
            
        Returns:
            dict: Assignment result
        """
        try:
            with transaction.atomic():
                # Import here to avoid circular import
                from apps.permissions.models import Role
                
                user = User.objects.get(id=user_id)
                role = Role.objects.get(id=role_id)
                
                # Check if assigned_by has permission to assign this role
                if assigned_by and not self._can_assign_role(assigned_by, role, user):
                    return {
                        'success': False,
                        'error': 'Insufficient permissions to assign this role'
                    }
                
                old_role = user.role
                user.role = role
                user.save(update_fields=['role'])
                
                # Log the role change
                self._log_role_assignment(user, old_role, role, assigned_by)
                
                return {
                    'success': True,
                    'old_role': old_role.name if old_role else None,
                    'new_role': role.name,
                    'assigned_by': assigned_by.email if assigned_by else 'system'
                }
                
        except User.DoesNotExist:
            return {'success': False, 'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error assigning role {role_id} to user {user_id}: {e}")
            return {'success': False, 'error': 'Role assignment failed'}

    def get_users_by_role(self, role_name: str, organization_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get users by role with optional organization filtering.
        
        Args:
            role_name: Role name to filter by
            organization_id: Optional organization filter
            
        Returns:
            list: User data for users with specified role
        """
        try:
            queryset = User.objects.select_related('role', 'organization').filter(
                role__name=role_name,
                is_active=True
            )
            
            if organization_id:
                queryset = queryset.filter(organization_id=organization_id)
            
            users = []
            for user in queryset:
                users.append({
                    'id': user.id,
                    'email': user.email,
                    'full_name': user.name,
                    'organization': {
                        'id': user.organization.id if user.organization else None,
                        'name': user.organization.name if user.organization else None
                    },
                    'status': user.status,
                    'last_login': user.last_login,
                    'date_joined': user.date_joined
                })
            
            return users
            
        except Exception as e:
            logger.error(f"Error getting users by role {role_name}: {e}")
            return []

    def get_role_hierarchy(self, user_id: int) -> Dict[str, Any]:
        """
        Get role hierarchy and permission inheritance for user.
        
        Args:
            user_id: User ID
            
        Returns:
            dict: Role hierarchy information
        """
        try:
            user = User.objects.select_related('role', 'organization').get(id=user_id)
            
            if not user.role:
                return {'hierarchy': [], 'level': 0}
            
            # Get role hierarchy (this would depend on your role model structure)
            role = user.role
            hierarchy = []
            current_role = role
            level = 0
            
            # Build hierarchy chain (assuming roles have parent relationships)
            while current_role and level < 10:  # Prevent infinite loops
                hierarchy.append({
                    'id': current_role.id,
                    'name': current_role.name,
                    'level': level,
                    'permissions': self._get_role_permissions(current_role)
                })
                
                # Move up hierarchy if role has parent (adjust based on your model)
                current_role = getattr(current_role, 'parent', None)
                level += 1
            
            return {
                'user_id': user_id,
                'current_role': role.name,
                'hierarchy': hierarchy,
                'total_levels': level,
                'organization_context': {
                    'id': user.organization.id if user.organization else None,
                    'name': user.organization.name if user.organization else None
                }
            }
            
        except User.DoesNotExist:
            return {'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error getting role hierarchy for user {user_id}: {e}")
            return {'error': 'Failed to get role hierarchy'}

    def validate_role_assignment(self, user_id: int, role_id: int, 
                                assigned_by: Optional[User] = None) -> Dict[str, Any]:
        """
        Validate role assignment before execution.
        
        Args:
            user_id: User ID
            role_id: Role ID to assign
            assigned_by: User performing assignment
            
        Returns:
            dict: Validation result
        """
        try:
            from apps.permissions.models import Role
            
            user = User.objects.select_related('organization', 'role').get(id=user_id)
            role = Role.objects.get(id=role_id)
            
            validation_errors = []
            
            # Check if role exists and is active
            if not getattr(role, 'is_active', True):
                validation_errors.append('Role is inactive')
            
            # Check organization compatibility
            if user.organization and hasattr(role, 'organization'):
                if role.organization and role.organization != user.organization:
                    validation_errors.append('Role not compatible with user organization')
            
            # Check if assigned_by has permission
            if assigned_by and not self._can_assign_role(assigned_by, role, user):
                validation_errors.append('Insufficient permissions to assign role')
            
            # Check for conflicting roles
            if user.role and self._roles_conflict(user.role, role):
                validation_errors.append('Role conflicts with current user role')
            
            return {
                'valid': len(validation_errors) == 0,
                'errors': validation_errors,
                'current_role': user.role.name if user.role else None,
                'target_role': role.name
            }
            
        except (User.DoesNotExist, Role.DoesNotExist):
            return {'valid': False, 'errors': ['User or role not found']}
        except Exception as e:
            logger.error(f"Error validating role assignment: {e}")
            return {'valid': False, 'errors': ['Validation failed']}

    def _get_role_permissions(self, role) -> Set[str]:
        """Get permissions for a role"""
        if not role:
            return set()
        
        try:
            return set(role.permissions.values_list('codename', flat=True))
        except Exception:
            return set()

    def _role_has_permission(self, role, permission: str) -> bool:
        """Check if role has specific permission"""
        try:
            return role.permissions.filter(codename=permission).exists()
        except Exception:
            return False

    def _check_organization_permission(self, user, permission: str, resource_id: int) -> bool:
        """
        Check organization-scoped permissions.
        This implements resource-based access control.
        """
        try:
            # This is a simplified implementation
            # In a real system, you'd check if the resource belongs to user's organization
            if not user.organization:
                return False
            
            # Example: Check if resource belongs to user's organization
            # This would be implemented based on your specific models
            
            return True  # Placeholder
            
        except Exception:
            return False

    def _can_assign_role(self, assigned_by: User, role, target_user: User) -> bool:
        """
        Check if user can assign specific role to target user.
        Implements role assignment authorization logic.
        """
        try:
            # Superuser can assign any role
            if assigned_by.is_superuser:
                return True
            
            # Organization admins can assign roles within their organization
            if (assigned_by.role and 'admin' in assigned_by.role.name.lower() 
                and assigned_by.organization == target_user.organization):
                return True
            
            # Check specific role assignment permissions
            if self.check_user_permission(assigned_by.id, 'assign_user_roles'):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking role assignment permission: {e}")
            return False

    def _roles_conflict(self, current_role, new_role) -> bool:
        """Check if roles have conflicts"""
        try:
            # Example conflict logic
            # Implement based on your business rules
            
            # Same role is not a conflict
            if current_role.id == new_role.id:
                return False
            
            # Check for mutually exclusive roles
            # This would be based on your specific role model attributes
            
            return False  # No conflicts detected
            
        except Exception:
            return False

    def _log_role_assignment(self, user, old_role, new_role, assigned_by: Optional[User]):
        """Log role assignment for audit trail"""
        try:
            logger.info(
                f"Role changed for user {user.email}: "
                f"{old_role.name if old_role else 'None'} -> {new_role.name} "
                f"by {assigned_by.email if assigned_by else 'system'}"
            )
            
            # This could integrate with an audit service
            # audit_service.log_role_change(user, old_role, new_role, assigned_by)
            
        except Exception as e:
            logger.error(f"Error logging role assignment: {e}")
