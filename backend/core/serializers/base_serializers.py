"""
Base Serializers and Mixins - Task 2.4.2

Foundational serializer classes and mixins for consistent API design.
These components reduce code duplication across all Django apps.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from typing import Dict, Any, Optional
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class BaseModelSerializer(serializers.ModelSerializer):
    """
    Enhanced base serializer with common functionality.
    Task 2.4.2: Foundation for all model serializers.
    """
    
    def __init__(self, *args, **kwargs):
        # Extract custom options
        self.read_only_fields_override = kwargs.pop('read_only_fields_override', None)
        self.exclude_fields = kwargs.pop('exclude_fields', None)
        
        super().__init__(*args, **kwargs)
        
        # Apply field modifications
        if self.read_only_fields_override:
            for field_name in self.read_only_fields_override:
                if field_name in self.fields:
                    self.fields[field_name].read_only = True
                    
        if self.exclude_fields:
            for field_name in self.exclude_fields:
                self.fields.pop(field_name, None)
    
    def validate(self, attrs):
        """Enhanced validation with common patterns"""
        attrs = super().validate(attrs)
        
        # Common validation patterns can be added here
        self._validate_business_rules(attrs)
        
        return attrs
    
    def _validate_business_rules(self, attrs):
        """Override in subclasses to add business rule validation"""
        pass
    
    def create(self, validated_data):
        """Enhanced create with logging and error handling"""
        try:
            instance = super().create(validated_data)
            self._log_creation(instance)
            return instance
        except Exception as e:
            self._log_creation_error(validated_data, e)
            raise
    
    def update(self, instance, validated_data):
        """Enhanced update with change tracking"""
        try:
            old_values = self._capture_old_values(instance, validated_data.keys())
            updated_instance = super().update(instance, validated_data)
            self._log_update(updated_instance, old_values, validated_data)
            return updated_instance
        except Exception as e:
            self._log_update_error(instance, validated_data, e)
            raise
    
    def _capture_old_values(self, instance, fields) -> Dict[str, Any]:
        """Capture old values for change tracking"""
        return {field: getattr(instance, field, None) for field in fields}
    
    def _log_creation(self, instance):
        """Log successful creation"""
        logger.info(f"Created {instance.__class__.__name__} with ID {instance.pk}")
    
    def _log_creation_error(self, validated_data, error):
        """Log creation error"""
        logger.error(f"Failed to create {self.Meta.model.__name__}: {error}")
    
    def _log_update(self, instance, old_values, new_values):
        """Log successful update"""
        changed_fields = [k for k in new_values if old_values.get(k) != new_values[k]]
        if changed_fields:
            logger.info(f"Updated {instance.__class__.__name__} {instance.pk}, fields: {changed_fields}")
    
    def _log_update_error(self, instance, validated_data, error):
        """Log update error"""
        logger.error(f"Failed to update {instance.__class__.__name__} {instance.pk}: {error}")


class TimestampMixin:
    """
    Mixin for serializers that need timestamp fields.
    Task 2.4.2: Reusable timestamp handling.
    """
    
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    
    def to_representation(self, instance):
        """Add formatted timestamps to representation"""
        data = super().to_representation(instance)
        
        # Add human-readable timestamps
        if hasattr(instance, 'created_at') and instance.created_at:
            data['created_at_display'] = instance.created_at.strftime('%Y-%m-%d %H:%M:%S')
            data['created_at_relative'] = self._get_relative_time(instance.created_at)
        
        if hasattr(instance, 'updated_at') and instance.updated_at:
            data['updated_at_display'] = instance.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            data['updated_at_relative'] = self._get_relative_time(instance.updated_at)
        
        return data
    
    def _get_relative_time(self, timestamp) -> str:
        """Get human-readable relative time"""
        try:
            now = timezone.now()
            diff = now - timestamp
            
            if diff.days > 0:
                return f"{diff.days} days ago"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"{hours} hours ago"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"{minutes} minutes ago"
            else:
                return "Just now"
        except Exception:
            return "Unknown"


class UserTrackingMixin:
    """
    Mixin for serializers that track user who created/updated records.
    Task 2.4.2: Consistent user tracking across apps.
    """
    
    created_by = serializers.SerializerMethodField()
    updated_by = serializers.SerializerMethodField()
    
    def get_created_by(self, obj):
        """Get creator information"""
        if hasattr(obj, 'created_by') and obj.created_by:
            return self._get_user_info(obj.created_by)
        return None
    
    def get_updated_by(self, obj):
        """Get updater information"""
        if hasattr(obj, 'updated_by') and obj.updated_by:
            return self._get_user_info(obj.updated_by)
        return None
    
    def _get_user_info(self, user) -> Dict[str, Any]:
        """Get standardized user information"""
        try:
            return {
                'id': user.id,
                'email': user.email,
                'full_name': getattr(user, 'name', f"{user.first_name} {user.last_name}".strip()),
                'role': user.role.name if hasattr(user, 'role') and user.role else None
            }
        except Exception:
            return {'id': user.id, 'email': user.email}


class OrganizationFilterMixin:
    """
    Mixin for serializers that need organization-based filtering.
    Task 2.4.2: Consistent organization handling.
    """
    
    organization = serializers.SerializerMethodField()
    organization_name = serializers.SerializerMethodField()
    
    def get_organization(self, obj):
        """Get organization information"""
        if hasattr(obj, 'organization') and obj.organization:
            return {
                'id': obj.organization.id,
                'name': obj.organization.name,
                'type': getattr(obj.organization, 'organization_type', 'unknown')
            }
        return None
    
    def get_organization_name(self, obj):
        """Get organization name for simple display"""
        if hasattr(obj, 'organization') and obj.organization:
            return obj.organization.name
        return None
    
    def validate(self, attrs):
        """Ensure organization consistency"""
        attrs = super().validate(attrs)
        
        # Get current user's organization from context
        request = self.context.get('request')
        if request and request.user and hasattr(request.user, 'organization'):
            user_org = request.user.organization
            
            # For creation, set organization if not provided
            if not self.instance and 'organization' not in attrs and user_org:
                attrs['organization'] = user_org
            
            # Validate organization access
            if 'organization' in attrs:
                target_org = attrs['organization']
                if not self._can_access_organization(request.user, target_org):
                    raise serializers.ValidationError(
                        "You don't have permission to access this organization"
                    )
        
        return attrs
    
    def _can_access_organization(self, user, organization) -> bool:
        """Check if user can access the organization"""
        try:
            # Superuser can access any organization
            if user.is_superuser:
                return True
            
            # Users can access their own organization
            if hasattr(user, 'organization') and user.organization == organization:
                return True
            
            # Additional access rules can be added here
            return False
            
        except Exception:
            return False


class StatusMixin:
    """
    Mixin for serializers with status fields.
    Task 2.4.2: Consistent status handling.
    """
    
    status_display = serializers.SerializerMethodField()
    can_change_status = serializers.SerializerMethodField()
    
    def get_status_display(self, obj):
        """Get human-readable status display"""
        if hasattr(obj, 'get_status_display'):
            return obj.get_status_display()
        elif hasattr(obj, 'status'):
            return obj.status.replace('_', ' ').title()
        return None
    
    def get_can_change_status(self, obj):
        """Check if current user can change status"""
        request = self.context.get('request')
        if not request or not request.user:
            return False
        
        # Override in subclasses for specific status change rules
        return self._check_status_change_permission(request.user, obj)
    
    def _check_status_change_permission(self, user, obj) -> bool:
        """Override in subclasses to implement status change rules"""
        return user.is_superuser


class AuditMixin:
    """
    Mixin for serializers that need audit information.
    Task 2.4.2: Consistent audit trails.
    """
    
    audit_info = serializers.SerializerMethodField()
    
    def get_audit_info(self, obj):
        """Get audit information"""
        try:
            audit_data = {
                'created_at': obj.created_at if hasattr(obj, 'created_at') else None,
                'updated_at': obj.updated_at if hasattr(obj, 'updated_at') else None,
                'version': getattr(obj, 'version', 1),
            }
            
            # Add user tracking if available
            if hasattr(obj, 'created_by') and obj.created_by:
                audit_data['created_by'] = obj.created_by.email
            
            if hasattr(obj, 'updated_by') and obj.updated_by:
                audit_data['updated_by'] = obj.updated_by.email
            
            # Add change count if available
            if hasattr(obj, 'activity_logs'):
                audit_data['change_count'] = obj.activity_logs.count()
            
            return audit_data
            
        except Exception as e:
            logger.error(f"Error getting audit info: {e}")
            return {}


class VersioningMixin:
    """
    Mixin for serializers that need version control.
    Task 2.4.2: Consistent versioning across models.
    """
    
    version = serializers.IntegerField(read_only=True)
    version_info = serializers.SerializerMethodField()
    
    def get_version_info(self, obj):
        """Get version information"""
        try:
            return {
                'current_version': getattr(obj, 'version', 1),
                'is_latest': True,  # Could be enhanced with actual version checking
                'last_modified': obj.updated_at if hasattr(obj, 'updated_at') else None
            }
        except Exception:
            return {'current_version': 1, 'is_latest': True}
    
    def update(self, instance, validated_data):
        """Update with version increment"""
        # Increment version on update
        if hasattr(instance, 'version'):
            instance.version = (instance.version or 0) + 1
        
        return super().update(instance, validated_data)
