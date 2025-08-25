"""
User Profile Service - Task 2.3.2

Reduces User model coupling by extracting profile-related operations
into a dedicated service with clean interfaces.
"""

from services.base_service import BaseService
from typing import Dict, Optional, Any, List
from django.contrib.auth import get_user_model
from django.db import transaction
from django.core.files.storage import default_storage
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class UserProfileService(BaseService):
    """
    Service for user profile operations, reducing direct User model coupling.
    Implements composition pattern for user profile functionality.
    """

    def __init__(self, user=None, organization=None, **kwargs):
        super().__init__(user=user, organization=organization)

    def get_service_name(self) -> str:
        """Return the name of this service for logging and identification"""
        return "user_profile_service"

    def get_user_profile(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive user profile data.
        
        Args:
            user_id: User ID
            
        Returns:
            dict: Profile data or None if user not found
        """
        try:
            user = User.objects.select_related(
                'organization', 'role', 'team', 'profile'
            ).get(id=user_id)
            
            return {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'full_name': user.name,
                'contact_number': user.contact_number,
                'address': user.address,
                'status': user.status,
                'is_active': user.is_active,
                'date_joined': user.date_joined,
                'last_login': user.last_login,
                'login_count': user.login_count,
                'sales_target': user.sales_target,
                'streak': user.streak,
                'must_change_password': user.must_change_password,
                
                # Related data - composition instead of direct access
                'organization': self._get_organization_summary(user),
                'role': self._get_role_summary(user),
                'team': self._get_team_summary(user),
                'profile': self._get_profile_details(user)
            }
            
        except User.DoesNotExist:
            logger.warning(f"User with ID {user_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error getting user profile {user_id}: {e}")
            return None

    def update_user_profile(self, user_id: int, profile_data: Dict[str, Any], 
                           updated_by: Optional[User] = None) -> Dict[str, Any]:
        """
        Update user profile with validation and audit trail.
        
        Args:
            user_id: User ID to update
            profile_data: Dictionary of fields to update
            updated_by: User making the update
            
        Returns:
            dict: Update result with success status
        """
        try:
            with transaction.atomic():
                user = User.objects.get(id=user_id)
                
                # Track changes for audit
                changes = {}
                updatable_fields = [
                    'first_name', 'last_name', 'contact_number', 'address',
                    'sales_target', 'streak'
                ]
                
                for field in updatable_fields:
                    if field in profile_data:
                        old_value = getattr(user, field)
                        new_value = profile_data[field]
                        if old_value != new_value:
                            changes[field] = {'old': old_value, 'new': new_value}
                            setattr(user, field, new_value)
                
                if changes:
                    user.save(update_fields=list(changes.keys()))
                    
                    # Log the changes for audit
                    self._log_profile_update(user, changes, updated_by)
                
                return {
                    'success': True,
                    'changes': changes,
                    'updated_fields': list(changes.keys())
                }
                
        except User.DoesNotExist:
            return {'success': False, 'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error updating user profile {user_id}: {e}")
            return {'success': False, 'error': 'Update failed'}

    def update_profile_picture(self, user_id: int, image_file, 
                              updated_by: Optional[User] = None) -> Dict[str, Any]:
        """Update user profile picture with security validation"""
        try:
            # Import here to avoid circular import
            from authentication.models import UserProfile
            
            user = User.objects.get(id=user_id)
            
            # Get or create profile
            profile, created = UserProfile.objects.get_or_create(user=user)
            
            # Validate file security (using existing validators)
            from deals.validators import validate_file_security
            validate_file_security(image_file)
            
            # Save old image path for cleanup
            old_image = profile.profile_picture
            
            # Update profile picture
            profile.profile_picture = image_file
            profile.save()
            
            # Clean up old file
            if old_image and old_image != image_file:
                try:
                    default_storage.delete(old_image.name)
                except Exception as e:
                    logger.warning(f"Could not delete old profile picture: {e}")
            
            # Log the change
            self._log_profile_update(
                user, 
                {'profile_picture': {'old': str(old_image), 'new': str(image_file)}},
                updated_by
            )
            
            return {
                'success': True,
                'image_url': profile.profile_picture.url if profile.profile_picture else None
            }
            
        except User.DoesNotExist:
            return {'success': False, 'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error updating profile picture for user {user_id}: {e}")
            return {'success': False, 'error': str(e)}

    def get_user_activity_summary(self, user_id: int, days: int = 30) -> Dict[str, Any]:
        """
        Get user activity summary without tight coupling to activity models.
        
        Args:
            user_id: User ID
            days: Number of days for activity summary
            
        Returns:
            dict: Activity summary
        """
        try:
            from datetime import datetime, timedelta
            from django.utils import timezone
            
            user = User.objects.get(id=user_id)
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)
            
            # Use composition to get related data without tight coupling
            activity_data = {
                'user_id': user_id,
                'period_days': days,
                'login_count': user.login_count,
                'last_login': user.last_login,
                'current_streak': user.streak,
                'status': user.status,
                'is_active': user.is_active
            }
            
            # Get related activity counts (using reverse relationships)
            try:
                # Use lazy evaluation to avoid N+1 queries
                activity_data.update({
                    'recent_sessions': user.usersession_set.filter(
                        created_at__gte=start_date
                    ).count() if hasattr(user, 'usersession_set') else 0,
                    
                    'security_events': user.security_events.filter(
                        created_at__gte=start_date
                    ).count() if hasattr(user, 'security_events') else 0,
                })
            except Exception:
                # Graceful degradation if relationships don't exist
                activity_data.update({
                    'recent_sessions': 0,
                    'security_events': 0,
                })
            
            return activity_data
            
        except User.DoesNotExist:
            return {'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error getting user activity summary {user_id}: {e}")
            return {'error': 'Failed to get activity summary'}

    def _get_organization_summary(self, user) -> Optional[Dict[str, Any]]:
        """Get organization summary without tight coupling"""
        if not user.organization:
            return None
        
        try:
            org = user.organization
            return {
                'id': org.id,
                'name': org.name,
                'type': getattr(org, 'organization_type', 'unknown'),
                'status': getattr(org, 'status', 'active')
            }
        except Exception:
            return {'id': user.organization.id, 'name': 'Unknown'}

    def _get_role_summary(self, user) -> Optional[Dict[str, Any]]:
        """Get role summary without tight coupling"""
        if not user.role:
            return None
        
        try:
            role = user.role
            return {
                'id': role.id,
                'name': role.name,
                'description': getattr(role, 'description', ''),
                'level': getattr(role, 'level', 0)
            }
        except Exception:
            return {'id': user.role.id, 'name': 'Unknown'}

    def _get_team_summary(self, user) -> Optional[Dict[str, Any]]:
        """Get team summary without tight coupling"""
        if not user.team:
            return None
        
        try:
            team = user.team
            return {
                'id': team.id,
                'name': team.name,
                'department': getattr(team, 'department', ''),
                'manager_id': getattr(team, 'manager_id', None)
            }
        except Exception:
            return {'id': user.team.id, 'name': 'Unknown'}

    def _get_profile_details(self, user) -> Dict[str, Any]:
        """Get profile details with graceful handling"""
        try:
            if hasattr(user, 'profile') and user.profile:
                profile = user.profile
                return {
                    'bio': profile.bio or '',
                    'profile_picture': profile.profile_picture.url if profile.profile_picture else None
                }
        except Exception:
            pass
        
        return {'bio': '', 'profile_picture': None}

    def _log_profile_update(self, user, changes: Dict, updated_by: Optional[User] = None):
        """Log profile updates for audit trail"""
        try:
            logger.info(
                f"Profile updated for user {user.email} by {updated_by.email if updated_by else 'system'}. "
                f"Changes: {list(changes.keys())}"
            )
            
            # This could integrate with an audit service if needed
            # audit_service.log_user_update(user, changes, updated_by)
            
        except Exception as e:
            logger.error(f"Error logging profile update: {e}")

    def validate_profile_data(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate profile data before updates.
        
        Returns:
            dict: Validation result with errors if any
        """
        errors = {}
        
        # Validate sales target
        if 'sales_target' in profile_data:
            try:
                sales_target = float(profile_data['sales_target'])
                if sales_target < 0:
                    errors['sales_target'] = 'Sales target cannot be negative'
            except (ValueError, TypeError):
                errors['sales_target'] = 'Invalid sales target value'
        
        # Validate streak
        if 'streak' in profile_data:
            try:
                streak = float(profile_data['streak'])
                if not 0.0 <= streak <= 5.0:
                    errors['streak'] = 'Streak must be between 0.0 and 5.0'
            except (ValueError, TypeError):
                errors['streak'] = 'Invalid streak value'
        
        # Validate contact number
        if 'contact_number' in profile_data:
            contact = profile_data['contact_number']
            if contact and len(contact) > 30:
                errors['contact_number'] = 'Contact number too long (max 30 characters)'
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors
        }
