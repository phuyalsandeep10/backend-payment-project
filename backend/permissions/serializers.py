from rest_framework import serializers
from .models import Permission, Role
from organization.models import Organization

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'category']

class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Permission.objects.all(),
        required=False
    )
    # Use a read-only field to show the organization name for context
    organization_name = serializers.CharField(source='organization.name', read_only=True)

    class Meta:
        model = Role
        fields = ['id', 'name', 'organization', 'organization_name', 'permissions']
        read_only_fields = ['organization', 'organization_name'] 