from rest_framework import serializers
from django.contrib.auth.models import Permission
from .models import Role
from apps.organization.models import Organization

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
    
    def validate(self, attrs):
        """Debug validation"""
        print(f"🔧 DEBUG - RoleSerializer validation:")
        print(f"  Attributes: {attrs}")
        print(f"  Instance: {self.instance}")
        print(f"  Partial: {self.partial}")
        
        # Check if permission IDs exist
        if 'permissions' in attrs:
            permission_ids = attrs['permissions']
            print(f"  Permission IDs: {[p.id if hasattr(p, 'id') else p for p in permission_ids]}")
            
            existing_permissions = Permission.objects.filter(
                id__in=[p.id if hasattr(p, 'id') else p for p in permission_ids]
            ).values_list('id', flat=True)
            print(f"  Existing permission IDs: {list(existing_permissions)}")
        
        return super().validate(attrs)
    
    def update(self, instance, validated_data):
        """Debug update process"""
        print(f"🔧 DEBUG - RoleSerializer update:")
        print(f"  Instance: {instance}")
        print(f"  Validated data: {validated_data}")
        return super().update(instance, validated_data) 