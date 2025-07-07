from rest_framework import serializers
from .models import Organization
from authentication.models import User
from permissions.models import Role

class OrganizationSerializer(serializers.ModelSerializer):
    """
    Serializer for the Organization model. Can be used for list and detail views.
    """
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    user_count = serializers.IntegerField(source='users.count', read_only=True)
    role_count = serializers.IntegerField(source='roles.count', read_only=True)

    class Meta:
        model = Organization
        fields = [
            'id', 'name', 'description', 'is_active', 'sales_goal',
            'created_at', 'created_by', 'created_by_username',
            'user_count', 'role_count'
        ]
        read_only_fields = ['created_by', 'created_by_username', 'user_count', 'role_count']

class OrganizationRegistrationSerializer(serializers.Serializer):
    """
    Validates the data for registering a new organization and its first admin.
    The creation logic is handled in the view.
    """
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(required=False, allow_blank=True)
    admin_first_name = serializers.CharField(max_length=150)
    admin_last_name = serializers.CharField(max_length=150)
    admin_email = serializers.EmailField()
    admin_password = serializers.CharField(write_only=True)

    def validate_name(self, value):
        if Organization.objects.filter(name__iexact=value).exists():
            raise serializers.ValidationError("An organization with this name already exists.")
        return value

    def validate_admin_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

class OrganizationWithAdminSerializer(serializers.Serializer):
    # Organization fields
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=1024, required=False, allow_blank=True)
    
    # Org Admin fields
    admin_email = serializers.EmailField()
    admin_first_name = serializers.CharField(max_length=255)
    admin_last_name = serializers.CharField(max_length=255)
    admin_password = serializers.CharField(write_only=True)

    def validate_admin_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        # Create organization
        org = Organization.objects.create(
            name=validated_data['name'],
            description=validated_data.get('description', '')
        )
        
        # Create all default roles for this organization
        default_roles = ['Organization Admin', 'Salesperson', 'Verifier']
        for role_name in default_roles:
            Role.objects.get_or_create(name=role_name, organization=org)
        
        # Get the Organization Admin role for this org
        org_admin_role = Role.objects.get(name='Organization Admin', organization=org)
        
        # Create the admin user
        admin_user = User.objects.create_user(
            email=validated_data['admin_email'],
            username=validated_data['admin_email'],
            first_name=validated_data['admin_first_name'],
            last_name=validated_data['admin_last_name'],
            password=validated_data['admin_password'],
            organization=org,
            role=org_admin_role
        )
        admin_user.is_active = True
        admin_user.save()
        return {'organization': org, 'admin_user': admin_user}