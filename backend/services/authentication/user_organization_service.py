"""
User Organization Service - Task 2.3.2

Reduces User model coupling by extracting organization-related operations
into a dedicated service with clean interfaces.
"""

from services.base_service import BaseService
from typing import Dict, Optional, Any, List
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q, Count
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class UserOrganizationService(BaseService):
    """
    Service for user-organization operations.
    Implements composition pattern to reduce User model coupling.
    """

    def __init__(self, user=None, organization=None, **kwargs):
        super().__init__(user=user, organization=organization)

    def get_service_name(self) -> str:
        """Return the name of this service for logging and identification"""
        return "user_organization_service"

    def get_organization_users(self, organization_id: int, 
                              include_inactive: bool = False) -> Dict[str, Any]:
        """
        Get all users in an organization with role distribution.
        
        Args:
            organization_id: Organization ID
            include_inactive: Whether to include inactive users
            
        Returns:
            dict: Organization users and statistics
        """
        try:
            # Import here to avoid circular imports
            from organization.models import Organization
            
            organization = Organization.objects.get(id=organization_id)
            
            # Build base queryset
            queryset = User.objects.select_related('role', 'team').filter(
                organization_id=organization_id
            )
            
            if not include_inactive:
                queryset = queryset.filter(is_active=True)
            
            users = []
            role_distribution = {}
            status_distribution = {}
            
            for user in queryset:
                user_data = {
                    'id': user.id,
                    'email': user.email,
                    'full_name': user.name,
                    'role': user.role.name if user.role else 'No Role',
                    'team': user.team.name if user.team else None,
                    'status': user.status,
                    'is_active': user.is_active,
                    'last_login': user.last_login,
                    'date_joined': user.date_joined,
                    'login_count': user.login_count
                }
                users.append(user_data)
                
                # Track statistics
                role_name = user.role.name if user.role else 'No Role'
                role_distribution[role_name] = role_distribution.get(role_name, 0) + 1
                status_distribution[user.status] = status_distribution.get(user.status, 0) + 1
            
            return {
                'organization': {
                    'id': organization.id,
                    'name': organization.name,
                    'type': getattr(organization, 'organization_type', 'unknown')
                },
                'users': users,
                'statistics': {
                    'total_users': len(users),
                    'active_users': len([u for u in users if u['is_active']]),
                    'role_distribution': role_distribution,
                    'status_distribution': status_distribution
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting organization users {organization_id}: {e}")
            return {'error': 'Failed to get organization users'}

    def transfer_user_organization(self, user_id: int, new_organization_id: int,
                                  transferred_by: Optional[User] = None) -> Dict[str, Any]:
        """
        Transfer user to different organization with proper validation.
        
        Args:
            user_id: User ID to transfer
            new_organization_id: Target organization ID
            transferred_by: User performing the transfer
            
        Returns:
            dict: Transfer result
        """
        try:
            with transaction.atomic():
                from organization.models import Organization
                
                user = User.objects.select_related('organization', 'role').get(id=user_id)
                new_org = Organization.objects.get(id=new_organization_id)
                old_org = user.organization
                
                # Validation
                if not self._can_transfer_user(user, new_org, transferred_by):
                    return {
                        'success': False,
                        'error': 'Insufficient permissions for user transfer'
                    }
                
                # Check if user's role is compatible with new organization
                role_compatibility = self._check_role_organization_compatibility(user.role, new_org)
                if not role_compatibility['compatible']:
                    # Handle role incompatibility
                    return {
                        'success': False,
                        'error': f"User role not compatible with target organization: {role_compatibility['reason']}"
                    }
                
                # Perform transfer
                user.organization = new_org
                user.save(update_fields=['organization'])
                
                # Handle related data cleanup/transfer
                self._handle_organization_transfer_cleanup(user, old_org, new_org)
                
                # Log the transfer
                self._log_organization_transfer(user, old_org, new_org, transferred_by)
                
                return {
                    'success': True,
                    'old_organization': old_org.name if old_org else 'None',
                    'new_organization': new_org.name,
                    'transferred_by': transferred_by.email if transferred_by else 'system'
                }
                
        except User.DoesNotExist:
            return {'success': False, 'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error transferring user {user_id} to org {new_organization_id}: {e}")
            return {'success': False, 'error': 'Transfer failed'}

    def get_user_organization_relationships(self, user_id: int) -> Dict[str, Any]:
        """
        Get user's organization-related relationships and data.
        
        Args:
            user_id: User ID
            
        Returns:
            dict: Organization relationships
        """
        try:
            user = User.objects.select_related('organization', 'role', 'team').get(id=user_id)
            
            if not user.organization:
                return {
                    'user_id': user_id,
                    'organization': None,
                    'relationships': {}
                }
            
            org = user.organization
            relationships = {
                'organization': {
                    'id': org.id,
                    'name': org.name,
                    'type': getattr(org, 'organization_type', 'unknown'),
                    'status': getattr(org, 'status', 'active')
                },
                'role_in_organization': {
                    'id': user.role.id if user.role else None,
                    'name': user.role.name if user.role else None
                },
                'team_in_organization': {
                    'id': user.team.id if user.team else None,
                    'name': user.team.name if user.team else None
                }
            }
            
            # Get organization-scoped data counts (without tight coupling)
            relationships['activity_summary'] = self._get_organization_activity_summary(user)
            
            return {
                'user_id': user_id,
                'organization': org.name,
                'relationships': relationships
            }
            
        except User.DoesNotExist:
            return {'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error getting user organization relationships {user_id}: {e}")
            return {'error': 'Failed to get relationships'}

    def get_organization_hierarchy(self, organization_id: int) -> Dict[str, Any]:
        """
        Get organization user hierarchy and reporting structure.
        
        Args:
            organization_id: Organization ID
            
        Returns:
            dict: Organization hierarchy
        """
        try:
            from organization.models import Organization
            
            organization = Organization.objects.get(id=organization_id)
            
            # Get users grouped by role
            users_by_role = {}
            users = User.objects.select_related('role', 'team').filter(
                organization_id=organization_id,
                is_active=True
            ).order_by('role__name', 'last_name', 'first_name')
            
            for user in users:
                role_name = user.role.name if user.role else 'No Role'
                if role_name not in users_by_role:
                    users_by_role[role_name] = []
                
                users_by_role[role_name].append({
                    'id': user.id,
                    'email': user.email,
                    'full_name': user.name,
                    'team': user.team.name if user.team else None,
                    'last_login': user.last_login
                })
            
            # Calculate hierarchy levels (simplified)
            hierarchy_levels = []
            role_order = ['super admin', 'organization admin', 'manager', 'salesperson', 'verifier']
            
            for role in role_order:
                matching_roles = [r for r in users_by_role.keys() if role.lower() in r.lower()]
                for role_name in matching_roles:
                    if role_name in users_by_role:
                        hierarchy_levels.append({
                            'role': role_name,
                            'level': len(hierarchy_levels),
                            'users': users_by_role[role_name],
                            'count': len(users_by_role[role_name])
                        })
            
            # Add any remaining roles not in the standard hierarchy
            for role_name, user_list in users_by_role.items():
                if not any(level['role'] == role_name for level in hierarchy_levels):
                    hierarchy_levels.append({
                        'role': role_name,
                        'level': len(hierarchy_levels),
                        'users': user_list,
                        'count': len(user_list)
                    })
            
            return {
                'organization': {
                    'id': organization.id,
                    'name': organization.name
                },
                'hierarchy': hierarchy_levels,
                'total_users': sum(level['count'] for level in hierarchy_levels),
                'total_levels': len(hierarchy_levels)
            }
            
        except Exception as e:
            logger.error(f"Error getting organization hierarchy {organization_id}: {e}")
            return {'error': 'Failed to get hierarchy'}

    def validate_organization_membership(self, user_id: int, organization_id: int,
                                       action: str = 'access') -> Dict[str, Any]:
        """
        Validate user's membership and permissions within organization.
        
        Args:
            user_id: User ID
            organization_id: Organization ID
            action: Action being validated
            
        Returns:
            dict: Validation result
        """
        try:
            user = User.objects.select_related('organization', 'role').get(id=user_id)
            
            validation_result = {
                'user_id': user_id,
                'organization_id': organization_id,
                'action': action,
                'valid': False,
                'reason': None
            }
            
            # Check if user belongs to organization
            if not user.organization or user.organization.id != organization_id:
                validation_result['reason'] = 'User does not belong to organization'
                return validation_result
            
            # Check if user is active
            if not user.is_active:
                validation_result['reason'] = 'User account is inactive'
                return validation_result
            
            # Check organization status
            if hasattr(user.organization, 'status') and user.organization.status != 'active':
                validation_result['reason'] = 'Organization is not active'
                return validation_result
            
            # Action-specific validation
            if action == 'admin_access':
                if not user.role or 'admin' not in user.role.name.lower():
                    validation_result['reason'] = 'User does not have admin role'
                    return validation_result
            
            validation_result['valid'] = True
            return validation_result
            
        except User.DoesNotExist:
            return {
                'valid': False,
                'reason': 'User not found'
            }
        except Exception as e:
            logger.error(f"Error validating organization membership: {e}")
            return {
                'valid': False,
                'reason': 'Validation failed'
            }

    def _can_transfer_user(self, user: User, new_org, transferred_by: Optional[User]) -> bool:
        """Check if user can be transferred to new organization"""
        try:
            # Superuser can transfer anyone
            if transferred_by and transferred_by.is_superuser:
                return True
            
            # Organization admins can transfer users within their scope
            if (transferred_by and transferred_by.role and 
                'admin' in transferred_by.role.name.lower()):
                
                # Can transfer if admin of source or target organization
                if (transferred_by.organization == user.organization or 
                    transferred_by.organization == new_org):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking transfer permission: {e}")
            return False

    def _check_role_organization_compatibility(self, role, organization) -> Dict[str, Any]:
        """Check if role is compatible with organization"""
        try:
            if not role:
                return {'compatible': True, 'reason': 'No role to check'}
            
            # Check if role is organization-specific
            if hasattr(role, 'organization') and role.organization:
                if role.organization != organization:
                    return {
                        'compatible': False,
                        'reason': f'Role belongs to different organization'
                    }
            
            # Check if role is allowed in organization type
            if (hasattr(organization, 'organization_type') and 
                hasattr(role, 'allowed_organization_types')):
                
                allowed_types = getattr(role, 'allowed_organization_types', [])
                if allowed_types and organization.organization_type not in allowed_types:
                    return {
                        'compatible': False,
                        'reason': f'Role not allowed for organization type {organization.organization_type}'
                    }
            
            return {'compatible': True}
            
        except Exception as e:
            logger.error(f"Error checking role compatibility: {e}")
            return {'compatible': False, 'reason': 'Compatibility check failed'}

    def _handle_organization_transfer_cleanup(self, user: User, old_org, new_org):
        """Handle cleanup when user transfers organizations"""
        try:
            # This would handle organization-specific data cleanup
            # Examples:
            # - Transfer or archive user's deals
            # - Update commission records
            # - Handle team assignments
            # - Clean up organization-specific permissions
            
            logger.info(f"Handling organization transfer cleanup for user {user.email}")
            
            # Placeholder for actual cleanup logic
            
        except Exception as e:
            logger.error(f"Error during organization transfer cleanup: {e}")

    def _get_organization_activity_summary(self, user: User) -> Dict[str, Any]:
        """Get user's activity summary within organization"""
        try:
            activity = {}
            
            # Safely get related counts without tight coupling
            try:
                # These would be implemented based on actual relationships
                activity['deals_count'] = getattr(user, 'deals', []).__len__() if hasattr(user, 'deals') else 0
                activity['clients_count'] = getattr(user, 'clients_created', []).__len__() if hasattr(user, 'clients_created') else 0
            except Exception:
                activity['deals_count'] = 0
                activity['clients_count'] = 0
            
            return activity
            
        except Exception as e:
            logger.error(f"Error getting organization activity summary: {e}")
            return {}

    def _log_organization_transfer(self, user: User, old_org, new_org, transferred_by: Optional[User]):
        """Log organization transfer for audit"""
        try:
            logger.info(
                f"Organization transfer: {user.email} from "
                f"{old_org.name if old_org else 'None'} to {new_org.name} "
                f"by {transferred_by.email if transferred_by else 'system'}"
            )
            
        except Exception as e:
            logger.error(f"Error logging organization transfer: {e}")
