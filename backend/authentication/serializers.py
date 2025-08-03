from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, UserSession, UserProfile
from user_agents import parse
from permissions.models import Role
from permissions.serializers import RoleSerializer
from organization.models import Organization
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
    profile = UserProfileSerializer(required=False)

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
        from team.serializers import TeamSerializer
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

class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating a new user (by an admin).
    If the caller does not provide a password, a random temporary password is generated.
    The view (`UserViewSet`) handles assigning the organization and, for super-admins, the role.
    """
    role = serializers.CharField(write_only=True, required=False)

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
            'role', 'contact_number', 'is_active',
            'address', 'status'
        )
        read_only_fields = ('id',)
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},
            'username': {'required': False, 'allow_blank': True}
        }
    
    def validate(self, data):
        # For non-superusers (e.g., org admins), 'role' is required.
        requesting_user = self.context['request'].user
        logger = logging.getLogger('django')
        logger.info(f"[UserCreateSerializer] Incoming data: {data}")
        try:
            if not requesting_user.is_superuser:
                if not data.get('role'):
                    logger.error('[UserCreateSerializer] Validation error: role is required')
                    raise serializers.ValidationError({'role': 'This field is required.'})
            return data
        except Exception as e:
            logger.error(f"[UserCreateSerializer] Validation error: {e}")
            raise

    def create(self, validated_data):
        from django.utils.crypto import get_random_string
        logger = logging.getLogger('django')
        logger.info("[UserCreateSerializer] Creating user with data: %r", validated_data)
        try:
            # Convert organization id to Organization instance if needed
            organization = validated_data.get('organization')
            if isinstance(organization, int):
                organization = Organization.objects.get(pk=organization)
                validated_data['organization'] = organization

            role_data = validated_data.pop('role', None)
            # Normalize role input
            if isinstance(role_data, str):
                role_key = role_data.strip().lower()
                role_name = self.ROLE_INPUT_MAP.get(role_key, role_data)
            else:
                role_name = role_data

            # The role can be a Role object (from super-admin) or a role name string (from org-admin).
            if isinstance(role_name, Role):
                validated_data['role'] = role_name
            elif role_name:
                # Look for an organization-specific role first, then a global one.
                try:
                    role = Role.objects.get(name__iexact=role_name, organization=organization)
                except Role.DoesNotExist:
                    try:
                        role = Role.objects.get(name__iexact=role_name, organization__isnull=True)
                    except Role.DoesNotExist:
                        logger.error(f"[UserCreateSerializer] Validation error: Role '{role_name}' not found.")
                        raise serializers.ValidationError({'role': f"Role '{role_name}' not found."})
                validated_data['role'] = role
            # If role_data is None, it's because a super-admin is creating a user,
            # and the view has already injected the correct Role object into validated_data.

            password = validated_data.pop('password', None) or get_random_string(length=12)

            if not validated_data.get('username'):
                validated_data['username'] = validated_data['email']

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
        except Exception as e:
            logger.error(f"[UserCreateSerializer] Exception during user creation: {e}")
            raise

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
        
        # Prevent salesperson and verifier roles from changing passwords
        restricted_roles = ['salesperson', 'verifier']
        role_name = user.role.name.lower() if user.role else ''
        
        if role_name in restricted_roles:
            raise serializers.ValidationError({
                'non_field_errors': 'You are not allowed to change your password. Please contact your administrator.'
            })
        
        # Check if the current password is correct
        if not user.check_password(attrs['current_password']):
            raise serializers.ValidationError({'current_password': 'The current password is not correct.'})
            
        # Check if the new passwords match
        if attrs['new_password'] != attrs.pop('confirm_password'):
            raise serializers.ValidationError({"new_password": "The new passwords do not match."})
            
        # Add password strength validation here if needed (optional)
        
        return attrs

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
        from team.serializers import TeamSerializer
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

    class Meta:
        model = User
        fields = (
            'first_name', 'last_name', 'contact_number', 'phoneNumber',
            'sales_target', 'profile', 'address', 'status'
        )

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', None)
        
        # Update User fields
        instance = super().update(instance, validated_data)

        # Update UserProfile fields
        if profile_data:
            profile, created = UserProfile.objects.get_or_create(user=instance)
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()
            
        # Return the updated instance, which will be serialized by the view
        return instance

    def to_representation(self, instance):
        """Return the detailed representation of the user after update."""
        return UserDetailSerializer(instance, context=self.context).data

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
