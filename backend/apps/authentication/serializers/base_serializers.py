"""
Base Authentication Serializers - Task 2.3.3

Focused, reusable serializer components that reduce complexity and duplication.
Uses service layer for business logic instead of embedding it in serializers.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from apps.authentication.models import UserProfile
from apps.authentication.services import profile_service

User = get_user_model()


class BaseUserSerializer(serializers.ModelSerializer):
    """
    Base user serializer with essential fields.
    Other serializers inherit from this to avoid duplication.
    """
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name']
    
    def get_full_name(self, obj):
        """Get user's full name using service layer"""
        try:
            profile_data = profile_service.get_user_profile(obj.id)
            if profile_data:
                return profile_data.get('full_name', '')
            return f"{obj.first_name} {obj.last_name}".strip() or obj.username
        except Exception:
            return f"{obj.first_name} {obj.last_name}".strip() or obj.username


class ProfileMixin:
    """
    Mixin for adding profile data to serializers using service layer.
    Reduces code duplication across user serializers.
    """
    
    def get_profile_data(self, obj):
        """Get profile data using service layer instead of direct model access"""
        try:
            profile_data = profile_service.get_user_profile(obj.id)
            if profile_data:
                return {
                    'profile_picture': profile_data['profile'].get('profile_picture'),
                    'bio': profile_data['profile'].get('bio', '')
                }
        except Exception:
            pass
        
        return {'profile_picture': None, 'bio': ''}


class RoleMixin:
    """
    Mixin for adding role data to serializers using service layer.
    """
    
    def get_role_data(self, obj):
        """Get role data using service layer"""
        try:
            from apps.authentication.services import role_service
            role_data = role_service.get_user_permissions(obj.id)
            if role_data and not role_data.get('error'):
                role_info = role_data.get('role', {})
                role_name = role_info.get('name')
                
                # Apply frontend naming convention
                if role_name == 'Organization Admin':
                    return 'org-admin'
                return role_name
        except Exception:
            pass
        
        return None


class OrganizationMixin:
    """
    Mixin for adding organization data using service layer.
    """
    
    def get_organization_data(self, obj):
        """Get organization data using service layer"""
        try:
            from apps.authentication.services import organization_service
            org_data = organization_service.get_user_organization_relationships(obj.id)
            if org_data and not org_data.get('error'):
                org_info = org_data.get('relationships', {}).get('organization', {})
                return {
                    'id': org_info.get('id'),
                    'name': org_info.get('name')
                }
        except Exception:
            pass
        
        return None


class UserLiteSerializer(BaseUserSerializer):
    """
    Lightweight user serializer for listings and references.
    Task 2.3.3: Focused component for specific use case.
    """
    
    class Meta(BaseUserSerializer.Meta):
        fields = BaseUserSerializer.Meta.fields + ['username']


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Focused serializer for user profile data only.
    Task 2.3.3: Separated from main user serializer.
    """
    
    class Meta:
        model = UserProfile
        fields = ['profile_picture', 'bio']
    
    def validate_profile_picture(self, value):
        """Validate profile picture using service layer"""
        if value:
            # Use service layer for validation instead of inline logic
            from apps.authentication.services import profile_service
            result = profile_service.update_profile_picture(
                user_id=self.instance.user.id if self.instance else None,
                image_file=value,
                updated_by=self.context.get('request').user if self.context.get('request') else None
            )
            
            if not result.get('success'):
                raise serializers.ValidationError(result.get('error', 'Invalid profile picture'))
        
        return value
