from rest_framework import serializers
from .models import Organization
from apps.authentication.models import User
from apps.permissions.models import Role
from apps.permissions.utils import assign_all_permissions_to_roles

class OrganizationSerializer(serializers.ModelSerializer):
    """
    Serializer for the Organization model. Can be used for list and detail views.
    """
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    user_count = serializers.IntegerField(source='users.count', read_only=True)
    role_count = serializers.IntegerField(source='roles.count', read_only=True)
    admin_email = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = [
            'id', 'name', 'description', 'is_active', 
            'created_at', 'created_by', 'created_by_username',
            'user_count', 'role_count', 'admin_email'
        ]
        read_only_fields = ['created_by', 'created_by_username', 'user_count', 'role_count', 'admin_email']

    def get_admin_email(self, obj):
        """Get the email of the organization admin."""
        try:
            admin_user = obj.users.filter(role__name='Organization Admin').first()
            return admin_user.email if admin_user else None
        except:
            return None
    
    def create(self, validated_data):
        """Create organization with default roles."""
        org = super().create(validated_data)
        
        # Always create the default roles for this org
        default_roles = [
            'Organization Admin',
            'Salesperson', 
            'Verifier',
            'Supervisor',
            'Team Member'
        ]
        
        for role_name in default_roles:
            Role.objects.get_or_create(name=role_name, organization=org)
        
        # Assign all permissions to all roles for this org
        assign_all_permissions_to_roles(org)
        
        return org

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
        
        # Always create the default roles for this org
        default_roles = [
            'Organization Admin',
            'Salesperson',
            'Verifier',
            'Team Member',
            'Supervisor',
        ]
        for role_name in default_roles:
            Role.objects.get_or_create(name=role_name, organization=org)
        
        # Assign all permissions to all roles for this org
        assign_all_permissions_to_roles(org)
        
        # Get the Org Admin role for this org
        org_admin_role = Role.objects.get(name='Organization Admin', organization=org)
        
        # Create the admin user for the organization
        admin_password = validated_data['admin_password']
        admin_user = User.objects.create_user(
            username=validated_data['admin_email'],  # Use email as username
            email=validated_data['admin_email'],
            password=admin_password,
            first_name=validated_data.get('admin_first_name', ''),
            last_name=validated_data.get('admin_last_name', ''),
            organization=org,
            role=org_admin_role,
            is_active=True,
            must_change_password=True  # Force password change on first login
        )
        
        # Send temporary password email to the new admin
        try:
            from apps.authentication.utils import send_temporary_password_email
            send_temporary_password_email(admin_user.email, admin_password)
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"Organization admin temporary password email sent to {admin_user.email}")
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to send temporary password email to {admin_user.email}: {e}")
        
        return {'organization': org, 'admin_user': admin_user}