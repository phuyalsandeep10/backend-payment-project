from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, UserSession, UserProfile
from user_agents import parse
from permissions.models import Role
from permissions.serializers import RoleSerializer
from organization.models import Organization

class UserLiteSerializer(serializers.ModelSerializer):
    """A lightweight serializer for User model, showing only essential info."""
    class Meta:
        model = User
        fields = ['id', 'username']

class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for the UserProfile model."""
    class Meta:
        model = UserProfile
        fields = ['profile_picture', 'bio']

class UserSerializer(serializers.ModelSerializer):
    """A detailed serializer for the User model."""
    teams = serializers.SerializerMethodField()
    role = RoleSerializer(read_only=True)
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    profile = UserProfileSerializer(required=False)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'organization', 'organization_name', 'role',
            'contact_number', 'is_active', 'profile', 'teams'
        ]
        read_only_fields = ['organization_name']

    def get_teams(self, obj):
        from team.serializers import TeamSerializer
        if hasattr(obj, 'teams'):
            return TeamSerializer(obj.teams.all(), many=True).data
        return []

class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating a new user (by an admin)."""
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), required=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'first_name', 'last_name', 'email', 'organization', 'role', 'contact_number', 'is_active')
        read_only_fields = ('id',)
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for the UserSession model."""
    device = serializers.SerializerMethodField()
    is_current = serializers.SerializerMethodField()

    class Meta:
        model = UserSession
        fields = ['id', 'ip_address', 'created_at', 'device', 'is_current']
        read_only_fields = fields

    def get_device(self, obj):
        if not obj.user_agent:
            return "Unknown Device"
        ua = parse(obj.user_agent)
        return f"{ua.browser.family} on {ua.os.family}"

    def get_is_current(self, obj):
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
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        user = self.context['request'].user
        if not user.check_password(attrs['old_password']):
            raise serializers.ValidationError({'old_password': 'Old password is not correct.'})
        # Add password strength validation here if needed
        return attrs

class UserDetailSerializer(serializers.ModelSerializer):
    """A detailed serializer for the User model, including nested profile and team info."""
    profile = UserProfileSerializer()
    teams = serializers.SerializerMethodField()
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    role = serializers.CharField(source='role.name', read_only=True)  # Role name as string for frontend compatibility

    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name', 
            'organization', 'organization_name', 'role', 
            'contact_number', 'is_active', 'profile', 'teams'
        )

    def get_teams(self, obj):
        # Avoid circular import
        from team.serializers import TeamSerializer
        # Check if the user is associated with any teams
        if hasattr(obj, 'teams'):
            return TeamSerializer(obj.teams.all(), many=True).data
        return "No Teams"

class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user and their nested profile."""
    profile = UserProfileSerializer(required=False)

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'contact_number', 'sales_target', 'profile')

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
            
        return instance

class AuthSuccessResponseSerializer(serializers.Serializer):
    """Generic response for successful authentication."""
    token = serializers.CharField(read_only=True)
    user = UserDetailSerializer(read_only=True)

class UserProfileResponseSerializer(serializers.Serializer):
    """Generic response for user profile requests."""
    user = UserDetailSerializer(read_only=True)

class MessageResponseSerializer(serializers.Serializer):
    """Generic response for simple messages (e.g., logout)."""
    message = serializers.CharField()

class ErrorResponseSerializer(serializers.Serializer):
    """Generic response for errors."""
    error = serializers.CharField()
    detail = serializers.CharField(required=False)
    code = serializers.CharField(required=False)
