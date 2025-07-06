from rest_framework import serializers
from .models import Organization
from authentication.models import User

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