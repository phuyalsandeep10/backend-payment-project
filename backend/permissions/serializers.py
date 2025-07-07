from rest_framework import serializers
from django.contrib.auth.models import Permission
from .models import Role
from organization.models import Organization

class PermissionSerializer(serializers.ModelSerializer):
    content_type = serializers.StringRelatedField(read_only=True)
    
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'content_type']

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
        read_only_fields = ['organization_name'] 