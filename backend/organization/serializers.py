from rest_framework import serializers
from .models import Organization
from authentication.models import User
from authentication.serializers import UserSerializer
from permissions.models import Role

class OrganizationSerializer(serializers.ModelSerializer):
    """
    Serializer for the Organization model.
    """
    class Meta:
        model = Organization
        fields = ['id', 'name', 'is_active', 'created_at']

class OrganizationDetailSerializer(OrganizationSerializer):
    """
    Extends the base serializer to include users and roles for detail views.
    """
    users = UserSerializer(many=True, read_only=True, source='user_set')
    roles = serializers.SerializerMethodField()

    class Meta(OrganizationSerializer.Meta):
        fields = OrganizationSerializer.Meta.fields + ['users', 'roles']

    def get_roles(self, obj):
        # This avoids circular dependency issues
        from permissions.serializers import RoleSerializer
        return RoleSerializer(obj.roles.all(), many=True).data

class OrganizationRegistrationSerializer(serializers.Serializer):
    """
    Serializer for registering a new organization along with its first admin.
    Returns the organization data and the newly created admin user.
    """
    # Request fields
    name = serializers.CharField(max_length=255)
    admin_email = serializers.EmailField()
    admin_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    # Response fields
    organization = OrganizationSerializer(read_only=True)
    admin_user = UserSerializer(read_only=True)

    def validate_name(self, value):
        if Organization.objects.filter(name=value).exists():
            raise serializers.ValidationError("An organization with this name already exists.")
        return value

    def validate_admin_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        # Create the organization
        org = Organization.objects.create(name=validated_data['name'])
        
        # Ensure the 'Org Admin' role exists for this organization.
        org_admin_role, _ = Role.objects.get_or_create(
            name='Org Admin',
            organization=org
        )

        # Create the organization admin
        user = User.objects.create_user(
            username=validated_data['admin_email'],
            email=validated_data['admin_email'],
            password=validated_data['admin_password'],
            organization=org,
            org_role=org_admin_role
        )
        
        return {
            'organization': org,
            'admin_user': user
        } 