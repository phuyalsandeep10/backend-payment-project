"""
Composition Mixins - Task 2.4.2

Advanced serializer composition patterns for complex data structures.
These mixins enable flexible serializer design and reduce code duplication.
"""

from rest_framework import serializers
from typing import Dict, Any, List, Optional, Type
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)


class NestedSerializerMixin:
    """
    Mixin for handling nested serializer operations.
    Task 2.4.2: Consistent nested data handling.
    """
    
    nested_serializers = {}  # Override in subclasses: {'field_name': SerializerClass}
    nested_write_fields = []  # Fields that allow nested writes
    
    def create(self, validated_data):
        """Enhanced create with nested serializer support"""
        nested_data = self._extract_nested_data(validated_data)
        
        # Create the main instance
        instance = super().create(validated_data)
        
        # Handle nested creates
        self._create_nested_objects(instance, nested_data)
        
        return instance
    
    def update(self, instance, validated_data):
        """Enhanced update with nested serializer support"""
        nested_data = self._extract_nested_data(validated_data)
        
        # Update the main instance
        instance = super().update(instance, validated_data)
        
        # Handle nested updates
        self._update_nested_objects(instance, nested_data)
        
        return instance
    
    def _extract_nested_data(self, validated_data):
        """Extract nested data from validated_data"""
        nested_data = {}
        
        for field_name in self.nested_write_fields:
            if field_name in validated_data:
                nested_data[field_name] = validated_data.pop(field_name)
        
        return nested_data
    
    def _create_nested_objects(self, instance, nested_data):
        """Create nested objects"""
        for field_name, data in nested_data.items():
            if field_name in self.nested_serializers:
                serializer_class = self.nested_serializers[field_name]
                self._create_nested_field(instance, field_name, serializer_class, data)
    
    def _update_nested_objects(self, instance, nested_data):
        """Update nested objects"""
        for field_name, data in nested_data.items():
            if field_name in self.nested_serializers:
                serializer_class = self.nested_serializers[field_name]
                self._update_nested_field(instance, field_name, serializer_class, data)
    
    def _create_nested_field(self, instance, field_name, serializer_class, data):
        """Create nested field objects"""
        try:
            if isinstance(data, list):
                # Handle many-to-many or one-to-many relationships
                for item_data in data:
                    item_data[self._get_parent_field_name()] = instance
                    serializer = serializer_class(data=item_data)
                    serializer.is_valid(raise_exception=True)
                    serializer.save()
            else:
                # Handle one-to-one or foreign key relationships
                data[self._get_parent_field_name()] = instance
                serializer = serializer_class(data=data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                
        except Exception as e:
            logger.error(f"Error creating nested field {field_name}: {e}")
            raise serializers.ValidationError(
                f"Error creating {field_name}: {str(e)}"
            )
    
    def _update_nested_field(self, instance, field_name, serializer_class, data):
        """Update nested field objects"""
        try:
            related_manager = getattr(instance, field_name)
            
            if isinstance(data, list):
                # Handle list of nested objects
                self._update_nested_list(related_manager, serializer_class, data)
            else:
                # Handle single nested object
                try:
                    nested_instance = related_manager.get()
                    serializer = serializer_class(nested_instance, data=data, partial=True)
                    serializer.is_valid(raise_exception=True)
                    serializer.save()
                except related_manager.model.DoesNotExist:
                    # Create if doesn't exist
                    data[self._get_parent_field_name()] = instance
                    serializer = serializer_class(data=data)
                    serializer.is_valid(raise_exception=True)
                    serializer.save()
                    
        except Exception as e:
            logger.error(f"Error updating nested field {field_name}: {e}")
            raise serializers.ValidationError(
                f"Error updating {field_name}: {str(e)}"
            )
    
    def _update_nested_list(self, related_manager, serializer_class, data_list):
        """Update a list of nested objects"""
        existing_objects = {obj.id: obj for obj in related_manager.all()}
        processed_ids = set()
        
        for item_data in data_list:
            item_id = item_data.get('id')
            
            if item_id and item_id in existing_objects:
                # Update existing object
                serializer = serializer_class(
                    existing_objects[item_id], 
                    data=item_data, 
                    partial=True
                )
                serializer.is_valid(raise_exception=True)
                serializer.save()
                processed_ids.add(item_id)
            else:
                # Create new object
                serializer = serializer_class(data=item_data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
        
        # Delete objects that weren't in the update data
        objects_to_delete = [
            obj for obj_id, obj in existing_objects.items() 
            if obj_id not in processed_ids
        ]
        for obj in objects_to_delete:
            obj.delete()
    
    def _get_parent_field_name(self):
        """Get the field name that references the parent object"""
        # This might need to be overridden based on your model structure
        return 'parent'


class CompositeValidationMixin:
    """
    Mixin for complex validation across multiple fields.
    Task 2.4.2: Advanced validation patterns.
    """
    
    composite_validators = []  # List of composite validator methods
    
    def validate(self, attrs):
        """Enhanced validation with composite validators"""
        attrs = super().validate(attrs)
        
        # Run composite validators
        for validator_name in self.composite_validators:
            if hasattr(self, validator_name):
                validator_method = getattr(self, validator_name)
                attrs = validator_method(attrs)
        
        return attrs
    
    def validate_date_range(self, attrs):
        """Validate date range consistency"""
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')
        
        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError(
                "End date must be after start date."
            )
        
        return attrs
    
    def validate_amount_consistency(self, attrs):
        """Validate amount field consistency"""
        total_amount = attrs.get('total_amount')
        received_amount = attrs.get('received_amount')
        
        if total_amount and received_amount:
            if received_amount > total_amount:
                raise serializers.ValidationError(
                    "Received amount cannot exceed total amount."
                )
        
        return attrs
    
    def validate_status_transitions(self, attrs):
        """Validate status transition rules"""
        new_status = attrs.get('status')
        
        if self.instance and new_status:
            old_status = self.instance.status
            
            if not self._is_valid_status_transition(old_status, new_status):
                raise serializers.ValidationError(
                    f"Cannot change status from {old_status} to {new_status}."
                )
        
        return attrs
    
    def _is_valid_status_transition(self, old_status, new_status):
        """Check if status transition is valid"""
        # Define valid transitions (override in subclasses)
        valid_transitions = {
            'draft': ['pending', 'cancelled'],
            'pending': ['approved', 'rejected', 'cancelled'],
            'approved': ['completed', 'cancelled'],
            'rejected': ['pending'],
            'completed': [],
            'cancelled': []
        }
        
        return new_status in valid_transitions.get(old_status, [])


class DynamicFieldsMixin:
    """
    Mixin for dynamic field inclusion/exclusion.
    Task 2.4.2: Flexible field handling.
    """
    
    def __init__(self, *args, **kwargs):
        # Extract dynamic field options
        fields = kwargs.pop('fields', None)
        exclude = kwargs.pop('exclude', None)
        
        super().__init__(*args, **kwargs)
        
        if fields is not None:
            # Only include specified fields
            allowed = set(fields)
            existing = set(self.fields)
            for field_name in existing - allowed:
                self.fields.pop(field_name)
        
        if exclude is not None:
            # Exclude specified fields
            for field_name in exclude:
                self.fields.pop(field_name, None)
    
    @classmethod
    def with_fields(cls, fields=None, exclude=None):
        """Factory method to create serializer with specific fields"""
        return lambda *args, **kwargs: cls(
            *args, **kwargs, fields=fields, exclude=exclude
        )


class ReadWriteSerializerMixin:
    """
    Mixin for different serializers for read/write operations.
    Task 2.4.2: Optimized read/write patterns.
    """
    
    read_serializer = None
    write_serializer = None
    
    def to_representation(self, instance):
        """Use read serializer for representation if specified"""
        if self.read_serializer and hasattr(self, 'context'):
            read_ser = self.read_serializer(instance, context=self.context)
            return read_ser.data
        
        return super().to_representation(instance)
    
    @classmethod
    def get_serializer_for_action(cls, action):
        """Get appropriate serializer based on action"""
        if action in ['create', 'update', 'partial_update']:
            return cls.write_serializer or cls
        else:
            return cls.read_serializer or cls


class ConditionalFieldsMixin:
    """
    Mixin for conditional field inclusion based on context.
    Task 2.4.2: Context-aware serialization.
    """
    
    conditional_fields = {}  # {'field_name': condition_function}
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Remove fields based on conditions
        request = self.context.get('request')
        user = request.user if request else None
        
        fields_to_remove = []
        for field_name, condition in self.conditional_fields.items():
            if field_name in self.fields:
                try:
                    if not condition(user, self.context):
                        fields_to_remove.append(field_name)
                except Exception as e:
                    logger.warning(f"Error evaluating condition for field {field_name}: {e}")
                    # Remove field if condition evaluation fails
                    fields_to_remove.append(field_name)
        
        for field_name in fields_to_remove:
            self.fields.pop(field_name, None)
    
    @staticmethod
    def require_permission(permission):
        """Factory for permission-based conditions"""
        def condition(user, context):
            return user and user.has_perm(permission)
        return condition
    
    @staticmethod
    def require_role(role_name):
        """Factory for role-based conditions"""
        def condition(user, context):
            return user and hasattr(user, 'role') and user.role and user.role.name == role_name
        return condition
    
    @staticmethod
    def require_ownership(owner_field='created_by'):
        """Factory for ownership-based conditions"""
        def condition(user, context):
            instance = context.get('instance')
            if not instance or not user:
                return False
            
            owner = getattr(instance, owner_field, None)
            return owner == user
        return condition


class PolymorphicSerializerMixin:
    """
    Mixin for polymorphic serialization based on object type.
    Task 2.4.2: Type-based serialization.
    """
    
    type_serializers = {}  # {'type_value': SerializerClass}
    type_field = 'type'
    
    def to_representation(self, instance):
        """Use type-specific serializer if available"""
        if hasattr(instance, self.type_field):
            type_value = getattr(instance, self.type_field)
            
            if type_value in self.type_serializers:
                serializer_class = self.type_serializers[type_value]
                serializer = serializer_class(instance, context=self.context)
                return serializer.data
        
        return super().to_representation(instance)
    
    def create(self, validated_data):
        """Create with type-specific handling"""
        type_value = validated_data.get(self.type_field)
        
        if type_value and type_value in self.type_serializers:
            serializer_class = self.type_serializers[type_value]
            serializer = serializer_class(data=validated_data, context=self.context)
            serializer.is_valid(raise_exception=True)
            return serializer.save()
        
        return super().create(validated_data)


class CacheableSerializerMixin:
    """
    Mixin for cacheable serialization.
    Task 2.4.2: Performance optimization through caching.
    """
    
    cache_timeout = 3600  # 1 hour default
    cache_key_fields = ['id']  # Fields to include in cache key
    
    def to_representation(self, instance):
        """Use cached representation if available"""
        from django.core.cache import cache
        
        try:
            cache_key = self._get_cache_key(instance)
            cached_data = cache.get(cache_key)
            
            if cached_data is not None:
                return cached_data
            
            # Generate representation and cache it
            data = super().to_representation(instance)
            cache.set(cache_key, data, self.cache_timeout)
            
            return data
            
        except Exception as e:
            logger.warning(f"Cache error in serializer: {e}")
            # Fall back to non-cached representation
            return super().to_representation(instance)
    
    def _get_cache_key(self, instance):
        """Generate cache key for instance"""
        key_parts = [self.__class__.__name__]
        
        for field in self.cache_key_fields:
            if hasattr(instance, field):
                value = getattr(instance, field)
                key_parts.append(f"{field}_{value}")
        
        # Add modification timestamp if available
        if hasattr(instance, 'updated_at'):
            timestamp = instance.updated_at.isoformat()
            key_parts.append(f"updated_{timestamp}")
        
        return "_".join(key_parts)
    
    @classmethod
    def clear_cache_for_instance(cls, instance):
        """Clear cache for specific instance"""
        from django.core.cache import cache
        
        try:
            # This is a simplified cache clearing
            # A full implementation might track all cache keys
            cache_key_pattern = f"{cls.__name__}_{instance.id}_*"
            # Clear cache (implementation depends on cache backend)
            
        except Exception as e:
            logger.warning(f"Error clearing cache: {e}")
