from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User
from permissions.models import Role
from permissions.serializers import RoleSerializer
# from team.serializers import TeamSerializer # This is moved to prevent circular import

class UserLiteSerializer(serializers.ModelSerializer):
    """
    A 'lite' serializer for the User model, exposing only essential, non-sensitive fields.
    """
    class Meta:
        model = User
        fields = ('id', 'username', 'first_name')

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model.
    """
    team = serializers.SerializerMethodField()
    org_role = RoleSerializer()

    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'email', 'organization', 'org_role', 'team', 'contact_number', 'is_active')
    
    def get_team(self, obj):
        from team.serializers import TeamSerializer
        if obj.team:
            return TeamSerializer(obj.team).data
        return None

class UserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new user.
    """
    org_role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), required=False, allow_null=True)
    
    class Meta:
        model = User
        fields = ('username', 'password', 'first_name', 'last_name', 'email', 'organization', 'org_role', 'team', 'contact_number', 'is_active')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    """
    Serializer for the login endpoint.
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)
            if not user:
                msg = 'Unable to log in with provided credentials.'
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = 'Must include "username" and "password".'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs 