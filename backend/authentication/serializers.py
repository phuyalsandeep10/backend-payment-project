from rest_framework import serializers, exceptions
from drf_yasg.utils import swagger_auto_schema
from django.contrib.auth import authenticate
from .models import User, UserSession
from user_agents import parse
from permissions.models import Role
from permissions.serializers import RoleSerializer
from django.core.validators import validate_email
from organization.models import Organization
from decimal import Decimal
# from team.serializers import TeamSerializer # This is moved to prevent circular import

class UserLiteSerializer(serializers.ModelSerializer):
    """
    A lightweight serializer for User model, showing only essential info.
    """
    class Meta:
        model = User
        fields = ['id', 'username']

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model.
    """
    teams = serializers.SerializerMethodField()
    role = RoleSerializer(read_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'email', 'organization', 'role', 'teams', 'contact_number', 'is_active')

    def get_teams(self, obj):
        from team.serializers import TeamSerializer
        if hasattr(obj, 'teams'):
            return TeamSerializer(obj.teams.all(), many=True).data
        return []

class UserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new user.
    """
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), required=False, allow_null=True)
    
    class Meta:
        model = User
        fields = ('username', 'password', 'first_name', 'last_name', 'email', 'organization', 'role', 'contact_number', 'is_active')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class UserSessionSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserSession model.
    Parses the user agent string into a readable format.
    """
    device = serializers.SerializerMethodField()

    class Meta:
        model = UserSession
        fields = ['id', 'ip_address', 'created_at', 'device']
        read_only_fields = fields

    def get_device(self, obj):
        if not obj.user_agent:
            return "Unknown Device"
        ua = parse(obj.user_agent)
        return f"{ua.browser.family} on {ua.os.family}"
    
    def to_representation(self, instance):
        """
        Add a flag to indicate if the session is the current one.
        """
        representation = super().to_representation(instance)
        current_session_key = self.context['request'].session.session_key
        # Note: DRF Token Auth is stateless, so we check against the token key
        auth_header = self.context['request'].headers.get('Authorization')
        if auth_header:
            try:
                current_token_key = auth_header.split(' ')[1]
                representation['is_current_session'] = (instance.session_key == current_token_key)
            except IndexError:
                representation['is_current_session'] = False
        else:
            representation['is_current_session'] = False
        return representation


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                                email=email, password=password)
            if not user:
                raise serializers.ValidationError("Invalid credentials")
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled")
        else:
            raise serializers.ValidationError("Must include 'email' and 'password'")

        attrs['user'] = user
        return attrs 

class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login with automatic streak calculation
    """
    email = serializers.EmailField(
        required=True,
        help_text="User's email address"
    )
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="User's password"
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                                email=email, password=password)
            if not user:
                raise serializers.ValidationError("Invalid email or password")
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled")
        else:
            raise serializers.ValidationError("Must include 'email' and 'password'")

        attrs['user'] = user
        return attrs

class UserLoginResponseSerializer(serializers.Serializer):
    """
    Serializer for auto-login response with streak calculation
    """
    token = serializers.CharField(help_text="Authentication token")
    user_id = serializers.IntegerField(help_text="User ID")
    username = serializers.CharField(help_text="Username")
    email = serializers.EmailField(help_text="User email")
    first_name = serializers.CharField(help_text="User first name")
    last_name = serializers.CharField(help_text="User last name")
    organization = serializers.CharField(help_text="Organization name")
    role = serializers.CharField(help_text="User role")
    sales_target = serializers.DecimalField(
        max_digits=15, 
        decimal_places=2, 
        help_text="User's sales target"
    )
    streak = serializers.IntegerField(help_text="Current streak (automatically calculated)")
    last_login = serializers.DateTimeField(help_text="Last login timestamp")
    message = serializers.CharField(help_text="Success message")

    class Meta:
        examples = {
            "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
            "user_id": 42,
            "username": "john_doe",
            "email": "john@company.com",
            "first_name": "John",
            "last_name": "Doe",
            "organization": "Tech Corp",
            "role": "Salesperson",
            "sales_target": "25000.00",
            "streak": 7,
            "message": "Login successful! Streak calculated and updated."
        }

class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """
    password = serializers.CharField(
        write_only=True, 
        min_length=8,
        help_text="Password (minimum 8 characters)"
    )
    confirm_password = serializers.CharField(
        write_only=True,
        help_text="Confirm password"
    )
    organization = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        help_text="Organization ID"
    )
    role = serializers.PrimaryKeyRelatedField(
        queryset=Role.objects.all(),
        required=False,
        help_text="Role ID (optional)"
    )

    class Meta:
        model = User
        fields = (
            'username', 'email', 'password', 'confirm_password', 
            'first_name', 'last_name', 'organization', 'role'
        )

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user

class UserRegistrationResponseSerializer(serializers.Serializer):
    """
    Serializer for user registration response
    """
    user_id = serializers.IntegerField(help_text="Created user ID")
    username = serializers.CharField(help_text="Username")
    email = serializers.EmailField(help_text="User email")
    organization = serializers.CharField(help_text="Organization name")
    message = serializers.CharField(help_text="Success message")

class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for password reset request
    """
    email = serializers.EmailField(
        required=True,
        help_text="Email address to send reset link"
    )

    def validate_email(self, value):
        validate_email(value)
        return value

class PasswordResetResponseSerializer(serializers.Serializer):
    """
    Serializer for password reset response
    """
    message = serializers.CharField(help_text="Status message")
    email = serializers.EmailField(help_text="Email where reset link was sent")

class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change
    """
    old_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="Current password"
    )
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        style={'input_type': 'password'},
        help_text="New password (minimum 8 characters)"
    )
    confirm_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="Confirm new password"
    )

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("New passwords do not match")
        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        return value

class PasswordChangeResponseSerializer(serializers.Serializer):
    """
    Serializer for password change response
    """
    message = serializers.CharField(help_text="Success message")

class UserDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for user detail information
    """
    organization_name = serializers.CharField(
        source='organization.name', 
        read_only=True,
        help_text="Organization name"
    )
    role_name = serializers.CharField(
        source='role.name', 
        read_only=True,
        help_text="Role name"
    )

    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name',
            'organization', 'organization_name', 'role', 'role_name',
            'sales_target', 'streak', 'is_active', 'date_joined', 'last_login'
        )
        read_only_fields = ('id', 'date_joined', 'last_login', 'streak')

class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user information
    """
    class Meta:
        model = User
        fields = (
            'first_name', 'last_name', 'sales_target', 'is_active'
        )

class LogoutResponseSerializer(serializers.Serializer):
    """
    Serializer for logout response
    """
    message = serializers.CharField(help_text="Logout confirmation message")

class SuperAdminLoginSerializer(serializers.Serializer):
    """
    Serializer for super admin login request
    """
    email = serializers.EmailField(
        required=True,
        help_text="Super admin email address"
    )
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="Super admin password"
    )

class SuperAdminLoginResponseSerializer(serializers.Serializer):
    """
    Serializer for super admin login response
    """
    message = serializers.CharField(help_text="Status message")
    session_id = serializers.CharField(help_text="Temporary session ID")
    otp_sent = serializers.BooleanField(help_text="Whether OTP was sent")

class SuperAdminVerifySerializer(serializers.Serializer):
    """
    Serializer for super admin OTP verification
    """
    session_id = serializers.CharField(
        required=True,
        help_text="Session ID from login step"
    )
    otp = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        help_text="6-digit OTP code"
    )

class SuperAdminVerifyResponseSerializer(serializers.Serializer):
    """
    Serializer for super admin OTP verification response
    """
    token = serializers.CharField(help_text="Authentication token")
    user_id = serializers.IntegerField(help_text="Super admin user ID")
    username = serializers.CharField(help_text="Super admin username")
    message = serializers.CharField(help_text="Success message")

class UserSessionDetailSerializer(serializers.Serializer):
    """
    Serializer for user session information
    """
    id = serializers.IntegerField(help_text="Session ID")
    session_key = serializers.CharField(help_text="Session key")
    ip_address = serializers.IPAddressField(help_text="IP address")
    user_agent = serializers.CharField(help_text="User agent string")
    device = serializers.CharField(help_text="Device type")
    location = serializers.CharField(help_text="Location (if available)")
    created_at = serializers.DateTimeField(help_text="Session creation time")
    last_activity = serializers.DateTimeField(help_text="Last activity time")
    is_current = serializers.BooleanField(help_text="Whether this is the current session")

class ErrorResponseSerializer(serializers.Serializer):
    """
    Serializer for error responses
    """
    error = serializers.CharField(help_text="Error message")
    detail = serializers.CharField(help_text="Detailed error description", required=False)
    code = serializers.CharField(help_text="Error code", required=False) 