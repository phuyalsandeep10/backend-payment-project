from rest_framework import serializers
from .models import Organization
from authentication.models import User

class OrganizationSerializer(serializers.ModelSerializer):
    """
    Serializer for the Organization model.
    """
    class Meta:
        model = Organization
        fields = ['id', 'name', 'is_active', 'created_at']

class OrgAdminSerializer(serializers.ModelSerializer):
    """
    Serializer for creating, listing, and updating Organization Admins.
    Handles password confirmation and optional password updates.
    """
    password = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'organization', 'is_active', 'password', 'password_confirm']
        
    def validate(self, attrs):
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')

        # On create (no instance), password is required
        if not self.instance and not password:
            raise serializers.ValidationError({"password": "Password is required for new admins."})

        # If one password field is entered, the other must be too, and they must match
        if password or password_confirm:
            if password != password_confirm:
                raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm', None)
        validated_data['role'] = User.Role.ORG_ADMIN
        user = User.objects.create_user(**validated_data)
        return user

    def update(self, instance, validated_data):
        # Remove password fields from validated_data to handle them separately
        validated_data.pop('password_confirm', None)
        password = validated_data.pop('password', None)
        
        # Update other user fields using the default update method
        instance = super().update(instance, validated_data)
        
        # Set new password if it was provided
        if password:
            instance.set_password(password)
            instance.save()
            
        return instance

class OrganizationRegistrationSerializer(serializers.Serializer):
    """
    Serializer for registering a new organization along with its first admin.
    """
    # Organization fields
    org_name = serializers.CharField(max_length=255)
    org_is_active = serializers.BooleanField(default=True)
    
    # Admin fields
    admin_email = serializers.EmailField()
    admin_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    admin_password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

    def validate_org_name(self, value):
        if Organization.objects.filter(name=value).exists():
            raise serializers.ValidationError("An organization with this name already exists.")
        return value

    def validate_admin_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    
    def validate(self, attrs):
        if attrs['admin_password'] != attrs['admin_password_confirm']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        # Create the organization
        organization = Organization.objects.create(
            name=validated_data['org_name'],
            is_active=validated_data['org_is_active']
        )
        
        # Create the organization admin
        admin_data = {
            'username': validated_data['admin_email'],  # Use email as username
            'email': validated_data['admin_email'],
            'password': validated_data['admin_password'],
            'role': User.Role.ORG_ADMIN,
            'organization': organization
        }
        User.objects.create_user(**admin_data)
        
        return organization 