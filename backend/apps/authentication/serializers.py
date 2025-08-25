from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, UserSession, UserProfile
from user_agents import parse
from apps.permissions.models import Role
from apps.permissions.serializers import RoleSerializer
from apps.organization.models import Organization
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from permissions.permissions import IsOrgAdminOrSuperAdmin
import logging

class UserLiteSerializer(serializers.ModelSerializer):
    """A lightweight serializer for User model, showing only essential info plus computed full_name."""

    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'full_name']

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username

class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for the UserProfile model."""
    class Meta:
        model = UserProfile
        fields = ['profile_picture', 'bio']

class UserSerializer(serializers.ModelSerializer):
    """A detailed serializer for the User model."""
    phoneNumber = serializers.CharField(source='contact_number', read_only=True)
    teams = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    profile = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'organization', 'organization_name', 'role',
            'contact_number', 'is_active', 'profile', 'teams',
            'status', 'address', 'phoneNumber'
        ]
        read_only_fields = ['organization_name']

    def get_teams(self, obj):
        from apps.team.serializers import TeamSerializer
        if hasattr(obj, 'teams'):
            return TeamSerializer(obj.teams.all(), many=True).data
        return []

    def get_role(self, obj):
        if obj.role:
            name = obj.role.name
            if name == 'Organization Admin':
                return 'org-admin'
            return name
        return None

    def get_profile(self, obj):
        """Safely retrieve user profile, creating it if missing."""
        try:
            if hasattr(obj, 'profile'):
                return UserProfileSerializer(obj.profile).data
            else:
                # Create profile if it doesn't exist
                from .models import UserProfile
                profile, created = UserProfile.objects.get_or_create(user=obj)
                return UserProfileSerializer(profile).data
        except Exception as e:
            # Return empty profile data on any error
            return {
                'profile_picture': None,
                'bio': None
            }

class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating a new user (by an admin).
    If the caller does not provide a password, a random temporary password is generated.
    The view (`UserViewSet`) handles assigning the organization and, for super-admins, the role.
    """
    role = serializers.CharField(write_only=True, required=False)
    organization = serializers.IntegerField(write_only=True, required=False)  # Expect integer ID

    ROLE_INPUT_MAP = {
        'salesperson': 'Salesperson',
        'verifier': 'Verifier',
        'supervisor': 'Supervisor',
        'team-member': 'Team Member',
        'organization admin': 'Organization Admin',
        'org-admin': 'Organization Admin',
    }

    class Meta:
        model = User
        fields = (
            'id', 'username', 'password', 'first_name', 'last_name', 'email',
            'role', 'organization', 'contact_number', 'is_active',
            'address', 'status'
        )
        read_only_fields = ('id',)
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},
            'username': {'required': False, 'allow_blank': True}
        }
    
    def validate(self, data):
        from .utils import validate_user_email
        from django.core.exceptions import ValidationError as DjangoValidationError
        
        # For non-superusers (e.g., org admins), 'role' is required.
        requesting_user = self.context['request'].user
        logger = logging.getLogger('django')
        logger.info(f"[UserCreateSerializer] Incoming data: {data}")
        logger.info(f"[UserCreateSerializer] Organization field: {data.get('organization')} (type: {type(data.get('organization'))})")
        
        try:
            # Validate role requirement for non-superusers
            if not requesting_user.is_superuser:
                if not data.get('role'):
                    logger.error('[UserCreateSerializer] Validation error: role is required')
                    raise serializers.ValidationError('This field is required.')
            
            # Enhanced email validation with normalization and duplicate checking
            email = data.get('email')
            if email:
                try:
                    # Get organization context for validation
                    organization = data.get('organization') or getattr(requesting_user, 'organization', None)
                    
                    # Use the comprehensive email validation utility
                    validated_email = validate_user_email(email, organization=organization)
                    data['email'] = validated_email
                    
                    logger.info(f"[UserCreateSerializer] Email validation successful: {email} -> {validated_email}")
                    
                except DjangoValidationError as e:
                    logger.error(f'[UserCreateSerializer] Email validation failed: {str(e)}')
                    # Convert Django ValidationError to DRF ValidationError with single message
                    raise serializers.ValidationError(str(e))
                except Exception as e:
                    logger.error(f'[UserCreateSerializer] Unexpected error during email validation: {str(e)}')
                    raise serializers.ValidationError('An error occurred while validating the email address. Please try again.')
            
            return data
            
        except serializers.ValidationError:
            # Re-raise DRF ValidationErrors as-is
            raise
        except Exception as e:
            logger.error(f"[UserCreateSerializer] Validation error: {e}")
            raise serializers.ValidationError('An error occurred during validation. Please try again.')

    def create(self, validated_data):
        from django.utils.crypto import get_random_string
        from django.db import IntegrityError
        from django.core.exceptions import ValidationError as DjangoValidationError
        
        logger = logging.getLogger('django')
        logger.info("[UserCreateSerializer] Creating user with data: %r", validated_data)
        
        try:
            # Handle role field - it might be a string from frontend or a Role object from view
            role_data = validated_data.get('role')
            if role_data:
                # Normalize role input if it's a string
                if isinstance(role_data, str):
                    role_key = role_data.strip().lower()
                    role_name = self.ROLE_INPUT_MAP.get(role_key, role_data)
                    # Remove the string role since we'll handle it in the view
                    validated_data.pop('role')
                elif hasattr(role_data, 'id'):  # It's a Role object
                    # Keep the Role object in validated_data
                    pass
                else:
                    # Remove invalid role data
                    validated_data.pop('role')
            else:
                # No role data provided, remove it
                validated_data.pop('role', None)

            password = validated_data.pop('password', None) or get_random_string(length=12)

            # Use normalized email for username if username is not provided
            if not validated_data.get('username'):
                validated_data['username'] = validated_data['email']

            # Email has already been validated and normalized in validate() method
            logger.info(f"[UserCreateSerializer] Creating user with normalized email: {validated_data['email']}")
            
            user = User.objects.create_user(password=password, **validated_data)

            # Set permanent password for salesperson and verifier roles
            permanent_password_roles = ['salesperson', 'verifier']
            role_name = user.role.name.lower() if user.role else ''
            
            if role_name in permanent_password_roles:
                user.must_change_password = False
            else:
                user.must_change_password = True
                
            user.save(update_fields=['must_change_password'])

            try:
                from authentication.utils import send_temporary_password_email
                send_temporary_password_email(user.email, password)
            except Exception as e:
                logger.warning(f'Failed to send temp password email: {e}')
                
            logger.info(f"[UserCreateSerializer] User created successfully: {user.email}")
            return user
            
        except IntegrityError as e:
            logger.error(f"[UserCreateSerializer] Database integrity error: {e}")
            if 'email' in str(e).lower():
                raise serializers.ValidationError('A user with this email address already exists.')
            else:
                raise serializers.ValidationError('A user with these details already exists.')
                
        except DjangoValidationError as e:
            logger.error(f"[UserCreateSerializer] Django validation error: {e}")
            raise serializers.ValidationError(str(e))
            
        except serializers.ValidationError:
            # Re-raise DRF ValidationErrors as-is
            raise
            
        except Exception as e:
            logger.error(f"[UserCreateSerializer] Unexpected error during user creation: {e}")
            raise serializers.ValidationError('An error occurred while creating the user. Please try again.')

class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for the UserSession model."""
    device = serializers.SerializerMethodField()
    is_current_session = serializers.SerializerMethodField()
    user_agent = serializers.CharField(read_only=True)

    class Meta:
        model = UserSession
        fields = ['id', 'ip_address', 'created_at', 'device', 'is_current_session', 'user_agent']
        read_only_fields = fields

    def get_device(self, obj):
        if not obj.user_agent:
            return "Unknown Device"
        ua = parse(obj.user_agent)
        return f"{ua.browser.family} on {ua.os.family}"

    def get_is_current_session(self, obj):
        auth_header = self.context['request'].headers.get('Authorization')
        if auth_header:
            try:
                current_token_key = auth_header.split(' ')[1]
                # This logic assumes the token IS the session key, which might not be true.
                return obj.session_key == current_token_key
            except IndexError:
                pass
        return False


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True, style={'input_type': 'password'})

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        if email and password:
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            if not user:
                raise serializers.ValidationError("Invalid credentials.", code='authorization')
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled.", code='authorization')
        else:
            raise serializers.ValidationError("Must include 'email' and 'password'.", code='authorization')
        attrs['user'] = user
        return attrs

class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for public user registration."""
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), required=True)
    organization = serializers.PrimaryKeyRelatedField(queryset=Organization.objects.all(), required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm', 'first_name', 'last_name', 'organization', 'role')

    def validate(self, attrs):
        if attrs['password'] != attrs.pop('password_confirm'):
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return super().validate(attrs)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for changing a user's password."""
    current_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        user = self.context['request'].user
        
        # Business requirement: Restrict password changes for certain roles
        # Keep your original business logic - only restrict specific roles that were originally restricted
        if user.role:
            role_name = user.role.name.lower()
            restricted_roles = ['salesperson', 'verifier']  # Your original restrictions
            
            if role_name in restricted_roles:
                # Send notification to Organization Admin about password change request
                self._notify_org_admin_password_request(user)
                
                raise serializers.ValidationError({
                    'non_field_errors': 'You are not allowed to change your password directly. Your Organization Admin has been notified of your request.'
                })
        
        # Check if the current password is correct
        if not user.check_password(attrs['current_password']):
            raise serializers.ValidationError({'current_password': 'The current password is not correct.'})
            
        # Check if the new passwords match
        if attrs['new_password'] != attrs.pop('confirm_password'):
            raise serializers.ValidationError({"new_password": "The new passwords do not match."})
            
        # Add password strength validation here if needed (optional)
        
        return attrs
    
    def _notify_org_admin_password_request(self, user):
        """Send notification to Organization Admin about password change request"""
        try:
            # Find Organization Admin for this user's organization
            if user.organization:
                org_admin_role = Role.objects.filter(
                    name='Organization Admin',
                    organization=user.organization
                ).first()
                
                if org_admin_role:
                    org_admins = User.objects.filter(
                        role=org_admin_role,
                        organization=user.organization,
                        is_active=True
                    )
                    
                    # Send email notification to all org admins
                    for org_admin in org_admins:
                        self._send_password_request_email(org_admin, user)
                        
                    # Log the notification
                    logging.getLogger('security').info(
                        f"Password change request notification sent for user {user.email} to org admins"
                    )
        except Exception as e:
            # Log error but don't fail the validation
            logging.getLogger('security').error(
                f"Failed to notify org admin about password request for {user.email}: {str(e)}"
            )
    
    def _send_password_request_email(self, org_admin, requesting_user):
        """Send email to org admin about password change request"""
        from django.core.mail import send_mail
        from django.conf import settings
        
        subject = f"Password Change Request - {requesting_user.first_name} {requesting_user.last_name}"
        message = f"""
Dear {org_admin.first_name},

{requesting_user.first_name} {requesting_user.last_name} ({requesting_user.email}) has requested a password change.

User Details:
- Name: {requesting_user.first_name} {requesting_user.last_name}
- Email: {requesting_user.email}
- Role: {requesting_user.role.name if requesting_user.role else 'No Role'}
- Organization: {requesting_user.organization.name if requesting_user.organization else 'No Organization'}

Please log into the admin panel to assign a new password for this user.

Best regards,
PRS System
        """
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [org_admin.email],
                fail_silently=False,
            )
        except Exception as e:
            logging.getLogger('security').error(
                f"Failed to send password request email to {org_admin.email}: {str(e)}"
            )

class UserDetailSerializer(serializers.ModelSerializer):
    """Serializer for comprehensive user details."""
    profile = UserProfileSerializer(required=False)
    phoneNumber = serializers.CharField(source='contact_number', read_only=True)
    teams = serializers.SerializerMethodField()
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    role = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name',
            'organization', 'organization_name', 'role',
            'contact_number', 'is_active', 'profile', 'teams',
            'address', 'status', 'phoneNumber'
        )

    def get_teams(self, obj):
        # Avoid circular import
        from apps.team.serializers import TeamSerializer
        # Check if the user is associated with any teams
        if hasattr(obj, 'teams'):
            return TeamSerializer(obj.teams.all(), many=True).data
        return "No Teams"

    def get_role(self, obj):
        if obj.role:
            name = obj.role.name
            if name == 'Organization Admin':
                return 'org-admin'
            return name
        return None

class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user and their nested profile."""
    profile = UserProfileSerializer(required=False)
    # Accept camelCase alias from frontend
    phoneNumber = serializers.CharField(source='contact_number', required=False, allow_blank=True)
    # Handle profile picture upload directly at top level
    profile_picture = serializers.ImageField(required=False, write_only=True, allow_null=True)

    class Meta:
        model = User
        fields = (
            'first_name', 'last_name', 'contact_number', 'phoneNumber',
            'sales_target', 'profile', 'address', 'status', 'profile_picture'
        )

    def update(self, instance, validated_data):
        print(f"=== UserUpdateSerializer.update called for user {instance.email} ===")
        print(f"Validated data keys: {list(validated_data.keys())}")
        print(f"Full validated_data: {validated_data}")
        
        profile_data = validated_data.pop('profile', None)
        profile_picture = validated_data.pop('profile_picture', None)
        
        print(f"Profile data: {profile_data}")
        print(f"Profile picture: {profile_picture}")
        print(f"Profile picture type: {type(profile_picture)}")
        
        # Update User fields
        instance = super().update(instance, validated_data)

        # Update UserProfile fields
        profile, created = UserProfile.objects.get_or_create(user=instance)
        print(f"Profile object created/retrieved: {created}")
        print(f"Profile object ID: {profile.id}")
        print(f"Profile before update: {profile.profile_picture}")
        
        # Handle nested profile data
        if profile_data:
            print(f"Updating profile with nested data: {profile_data}")
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
        
        # Handle profile picture upload
        if profile_picture:
            print(f"Setting profile picture: {profile_picture}")
            print(f"Profile picture name: {profile_picture.name}")
            print(f"Profile picture size: {profile_picture.size}")
            profile.profile_picture = profile_picture
            print(f"Profile picture after assignment: {profile.profile_picture}")
        else:
            print("No profile picture provided in the request")
            
        try:
            profile.save()
            print(f"Profile saved successfully. Final profile_picture: {profile.profile_picture}")
            print(f"Profile picture URL: {profile.profile_picture.url if profile.profile_picture else 'None'}")
        except Exception as e:
            print(f"Error saving profile: {e}")
            raise
            
        # Refresh the instance to get the latest related data
        instance.refresh_from_db()
        if hasattr(instance, 'profile'):
            instance.profile.refresh_from_db()
            
        # Return the updated instance, which will be serialized by the view
        return instance

    def to_representation(self, instance):
        """Return the detailed representation of the user after update."""
        # Ensure we have fresh profile data
        instance.refresh_from_db()
        
        # Get fresh profile with updated profile picture
        try:
            if hasattr(instance, 'profile'):
                instance.profile.refresh_from_db()
        except:
            pass
            
        data = UserDetailSerializer(instance, context=self.context).data
        print(f"Final serializer response data: {data}")
        return data

class AuthSuccessResponseSerializer(serializers.Serializer):
    """Generic response for successful authentication."""
    token = serializers.CharField(read_only=True)
    user = UserDetailSerializer(read_only=True)

class OTPSerializer(serializers.Serializer):
    """Serializer for OTP verification."""
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)

class PasswordResetSerializer(serializers.Serializer):
    """Serializer for resetting password with a token."""
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs.pop('confirm_password'):
            raise serializers.ValidationError({"new_password": "The new passwords do not match."})
        return attrs

class SuperUserLoginSerializer(serializers.Serializer):
    """
    Serializer for Super Admin login. Validates credentials and ensures the user is a superuser.
    """
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError("Email and password are required.", code='authorization')

        user = authenticate(request=self.context.get('request'), email=email, password=password)

        if not user:
            raise serializers.ValidationError("Invalid credentials.", code='authorization')

        if not user.is_superuser:
            raise serializers.ValidationError("You do not have permission to perform this action.", code='authorization')

        attrs['user'] = user
        return attrs

# ===================== AUXILIARY SERIALIZERS =====================

class RoleSerializer(serializers.ModelSerializer):
    """A simple serializer for the Role model to show its name."""
    class Meta:
        model = Role
        fields = ['id', 'name']

class MessageResponseSerializer(serializers.Serializer):
    message = serializers.CharField()

class ErrorResponseSerializer(serializers.Serializer):
    """Generic response for errors."""
    error = serializers.CharField()
    detail = serializers.CharField(required=False)
    code = serializers.CharField(required=False)
