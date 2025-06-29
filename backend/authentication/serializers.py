from rest_framework import serializers, exceptions
from django.contrib.auth import authenticate
from .models import User, UserSession
from user_agents import parse
from permissions.models import Role
from permissions.serializers import RoleSerializer
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
    Serializer for the login endpoint.
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                                email=email, password=password)
            if not user:
                msg = 'Unable to log in with provided credentials.'
                raise exceptions.AuthenticationFailed(msg, code='authorization')
        else:
            msg = 'Must include "email" and "password".'
            raise exceptions.AuthenticationFailed(msg, code='authorization')

        attrs['user'] = user
        return attrs 