"""
User Management Serializers - Task 2.3.3

Focused serializers for user CRUD operations using service layer.
Extracts business logic to services for better separation of concerns.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from apps.authentication.models import UserProfile
from apps.authentication.services import (
    profile_service,
    role_service,
    organization_service,
    password_policy_service
)
from .base_serializers import BaseUserSerializer, ProfileMixin, RoleMixin, OrganizationMixin

User = get_user_model()

# Safe import for Organization model
try:
    from apps.organization.models import Organization
    _organization_queryset = Organization.objects.none()
except ImportError:
    _organization_queryset = None


class UserSerializer(BaseUserSerializer, ProfileMixin, RoleMixin, OrganizationMixin):
    """
    Standard user serializer using service layer.
    Task 2.3.3: Simplified with mixins and service integration.
    """
    phoneNumber = serializers.CharField(source='contact_number', read_only=True)
    organization_name = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    profile = serializers.SerializerMethodField()
    teams = serializers.SerializerMethodField()
    
    class Meta(BaseUserSerializer.Meta):
        fields = BaseUserSerializer.Meta.fields + [
            'username', 'organization_name', 'role', 'contact_number',
            'is_active', 'profile', 'teams', 'status', 'address', 'phoneNumber'
        ]
    
    def get_organization_name(self, obj):
        """Get organization name using service layer"""
        org_data = self.get_organization_data(obj)
        return org_data['name'] if org_data else None
    
    def get_role(self, obj):
        """Get role using service layer"""
        return self.get_role_data(obj)
    
    def get_profile(self, obj):
        """Get profile using service layer"""
        return self.get_profile_data(obj)
    
    def get_teams(self, obj):
        """Get teams data - simplified to reduce complexity"""
        try:
            # Use relationship service for team data
            from apps.authentication.services import relationship_service
            relationships = relationship_service.get_user_related_counts(obj.id)
            
            # Simplified team data - could be expanded with a dedicated team service
            if obj.team:
                return [{
                    'id': obj.team.id,
                    'name': obj.team.name
                }]
            return []
        except Exception:
            return []


class UserDetailSerializer(UserSerializer):
    """
    Detailed user serializer for comprehensive user information.
    Task 2.3.3: Inherits from UserSerializer to reduce duplication.
    """
    activity_summary = serializers.SerializerMethodField()
    permissions_summary = serializers.SerializerMethodField()
    
    class Meta(UserSerializer.Meta):
        fields = UserSerializer.Meta.fields + [
            'activity_summary', 'permissions_summary'
        ]
    
    def get_activity_summary(self, obj):
        """Get user activity summary using service layer"""
        try:
            return profile_service.get_user_activity_summary(obj.id, days=30)
        except Exception:
            return {}
    
    def get_permissions_summary(self, obj):
        """Get permissions summary using service layer"""
        try:
            permissions_data = role_service.get_user_permissions(obj.id)
            if permissions_data and not permissions_data.get('error'):
                return {
                    'role': permissions_data.get('role', {}).get('name'),
                    'permission_count': permissions_data.get('permission_count', 0),
                    'is_superuser': permissions_data.get('is_superuser', False)
                }
        except Exception:
            pass
        return {}


class UserCreateSerializer(serializers.ModelSerializer):
    """
    Focused serializer for user creation using service layer.
    Task 2.3.3: Extracts business logic to services.
    """
    role = serializers.CharField(write_only=True, required=False)
    organization = serializers.PrimaryKeyRelatedField(
        queryset=_organization_queryset,  # Will be updated in __init__ based on user permissions
        required=False,
        allow_null=True
    )
    
    def to_internal_value(self, data):
        """Convert organization string to integer if needed"""
        if 'organization' in data and isinstance(data['organization'], str):
            try:
                # Try to convert string to integer
                data = data.copy() if hasattr(data, 'copy') else dict(data)
                data['organization'] = int(data['organization'])
            except (ValueError, TypeError):
                pass  # Let the field validation handle the error
        return super().to_internal_value(data)
    password = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = User
        fields = [
            'email', 'first_name', 'last_name', 'username',
            'contact_number', 'address', 'role', 'organization', 'password'
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Set organization queryset based on user permissions
        request = self.context.get('request')
        if request and request.user:
            try:
                # Use organization service to get available organizations
                from apps.organization.models import Organization
                if request.user.is_superuser:
                    self.fields['organization'].queryset = Organization.objects.all()
                elif request.user.organization:
                    self.fields['organization'].queryset = Organization.objects.filter(
                        id=request.user.organization.id
                    )
                else:
                    self.fields['organization'].queryset = Organization.objects.none()
            except Exception:
                from apps.organization.models import Organization
                self.fields['organization'].queryset = Organization.objects.all()
    
    def validate_email(self, value):
        """Validate email uniqueness"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email already exists.")
        return value
    
    def validate_password(self, value):
        """Validate password using service layer"""
        if value:
            # Use password policy service for validation
            validation_result = password_policy_service.validate_password(
                value,
                organization_id=self.initial_data.get('organization')
            )
            
            if not validation_result['is_valid']:
                raise serializers.ValidationError(validation_result['errors'])
        
        return value
    
    def validate_role(self, value):
        """Validate role assignment using service layer"""
        if value:
            try:
                from apps.permissions.models import Role
                
                # Get organization from the request data
                organization_id = self.initial_data.get('organization')
                if organization_id:
                    role = Role.objects.get(name=value, organization_id=organization_id)
                else:
                    # Fallback to first role with this name if no organization specified
                    role = Role.objects.filter(name=value).first()
                    if not role:
                        raise Role.DoesNotExist()
                
                # For new user creation, we skip the role assignment validation
                # since the user doesn't exist yet. We only validate that the role
                # exists and belongs to the correct organization.
                request = self.context.get('request')
                if request and request.user and request.user.is_authenticated:
                    # Check if the requesting user has permission to assign this role
                    if not self._can_assign_role(request.user, role):
                        raise serializers.ValidationError("Insufficient permissions to assign this role.")
                else:
                    # If user is not authenticated, provide more detailed error info
                    user_info = "None" if not request else str(request.user)
                    auth_info = "N/A" if not request or not request.user else str(request.user.is_authenticated)
                    raise serializers.ValidationError(f"Authentication required to assign roles. User: {user_info}, Authenticated: {auth_info}")
                        
                return value
                
            except Role.DoesNotExist:
                raise serializers.ValidationError(f"Role '{value}' does not exist for the specified organization.")
        
        return value
    
    def _can_assign_role(self, user, role):
        """Check if user can assign this role"""
        # Super admin can assign any role
        if user.is_superuser:
            return True
            
        # Organization admin can assign roles within their organization
        if hasattr(user, 'role') and user.role:
            if user.role.name.strip().replace('-', ' ').lower() in ['organization admin', 'org admin']:
                # Check if role belongs to same organization
                if hasattr(role, 'organization') and role.organization:
                    return user.organization == role.organization
                return True
        
        return False
    
    def create(self, validated_data):
        """Create user using service layer logic"""
        # Extract role and handle it separately
        role_name = validated_data.pop('role', None)
        password = validated_data.pop('password', None)
        
        # Generate password if not provided and set must_change_password flag
        password_was_generated = False
        if not password:
            organization_id = validated_data.get('organization').id if validated_data.get('organization') else None
            password = password_policy_service.generate_secure_password(
                organization_id=organization_id
            )
            password_was_generated = True
        
        # Create user
        user = User.objects.create_user(
            password=password,
            **validated_data
        )
        
        # Set must_change_password flag for users with generated passwords
        if password_was_generated:
            user.must_change_password = True
            user.save(update_fields=['must_change_password'])
        
        # Assign role - either provided or default based on context
        request = self.context.get('request')
        target_role_name = role_name
        
        # If no role provided, determine default role based on who's creating the user
        if not target_role_name and request and request.user:
            if request.user.is_superuser:
                # Superuser creating an org admin
                target_role_name = "Organization Admin"
            elif hasattr(request.user, 'role') and request.user.role and request.user.role.name == "Organization Admin":
                # Org admin creating a regular user - default to a basic role
                target_role_name = "Salesperson"  # or whatever default role you prefer
        
        if target_role_name:
            try:
                from apps.permissions.models import Role
                
                # Get role for the user's organization
                organization = user.organization
                if organization:
                    role = Role.objects.get(name=target_role_name, organization=organization)
                else:
                    # Fallback for system-wide roles
                    role = Role.objects.get(name=target_role_name, organization__isnull=True)
                
                role_result = role_service.assign_role_to_user(
                    user_id=user.id,
                    role_id=role.id,
                    assigned_by=request.user if request else None
                )
                
                if not role_result['success']:
                    # Role assignment failure should not be silent - it's critical
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.error(f"CRITICAL: Role assignment failed for new user {user.email}: {role_result['error']}")
                    # Delete the user since role assignment failed
                    user.delete()
                    raise serializers.ValidationError(f"Role assignment failed: {role_result['error']}")
                    
            except Role.DoesNotExist:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"CRITICAL: Role '{target_role_name}' not found for organization {organization.name if organization else 'None'}")
                user.delete()
                raise serializers.ValidationError(f"Role '{target_role_name}' does not exist for this organization")
                    
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"CRITICAL: Error assigning role to new user {user.email}: {e}")
                # Delete the user since role assignment failed
                user.delete()
                raise serializers.ValidationError(f"Failed to assign role: {str(e)}")
        else:
            # No role to assign - this might be intentional for some use cases
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"No role assigned to new user {user.email} - this may be intentional")
        
        # Send temporary password email
        try:
            from apps.authentication.utils import send_temporary_password_email
            send_temporary_password_email(user.email, password)
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"Temporary password email sent to {user.email}")
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to send temporary password email to {user.email}: {e}")
        
        # Add password to history
        from django.contrib.auth.hashers import make_password
        password_policy_service.add_password_to_history(user, make_password(password))
        
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Focused serializer for user updates using service layer.
    Task 2.3.3: Uses profile service for nested updates.
    """
    profile = serializers.DictField(write_only=True, required=False)
    phoneNumber = serializers.CharField(source='contact_number', required=False, allow_blank=True)
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'contact_number', 'address',
            'sales_target', 'streak', 'profile', 'phoneNumber'
        ]
    
    def validate(self, attrs):
        """Validate update data using service layer"""
        profile_data = attrs.pop('profile', {})
        
        # Validate main user data using profile service
        if attrs:
            validation_result = profile_service.validate_profile_data(attrs)
            if not validation_result['is_valid']:
                raise serializers.ValidationError(validation_result['errors'])
        
        # Store profile data for update method
        self._profile_data = profile_data
        return attrs
    
    def update(self, instance, validated_data):
        """Update user using service layer"""
        request = self.context.get('request')
        updated_by = request.user if request else None
        
        # Update main user fields using service
        if validated_data:
            result = profile_service.update_user_profile(
                user_id=instance.id,
                profile_data=validated_data,
                updated_by=updated_by
            )
            
            if not result['success']:
                raise serializers.ValidationError(result.get('error', 'Update failed'))
        
        # Update profile data if provided
        if hasattr(self, '_profile_data') and self._profile_data:
            # Handle profile picture separately if provided
            if 'profile_picture' in self._profile_data:
                profile_result = profile_service.update_profile_picture(
                    user_id=instance.id,
                    image_file=self._profile_data['profile_picture'],
                    updated_by=updated_by
                )
                
                if not profile_result['success']:
                    raise serializers.ValidationError(
                        f"Profile picture update failed: {profile_result.get('error')}"
                    )
            
            # Update other profile fields
            other_profile_data = {k: v for k, v in self._profile_data.items() if k != 'profile_picture'}
            if other_profile_data:
                # Update profile using Django ORM for non-complex fields
                try:
                    from apps.authentication.models import UserProfile
                    profile, created = UserProfile.objects.get_or_create(user=instance)
                    
                    for field, value in other_profile_data.items():
                        if hasattr(profile, field):
                            setattr(profile, field, value)
                    
                    profile.save()
                except Exception as e:
                    raise serializers.ValidationError(f"Profile update failed: {str(e)}")
        
        # Refresh instance to get updated data
        instance.refresh_from_db()
        return instance
