"""
Core Reusable Serializers Library - Task 2.4.2

Comprehensive serializer components for consistent API design across all apps.
Reduces duplication and provides common patterns for complex serializations.
"""

# Import all reusable components for easy access
from .base_serializers import (
    BaseModelSerializer,
    TimestampMixin,
    UserTrackingMixin,
    OrganizationFilterMixin
)

from .validation_mixins import (
    EmailValidationMixin,
    PhoneValidationMixin,
    DecimalValidationMixin,
    DateValidationMixin,
    FileValidationMixin
)

from .field_libraries import (
    MoneyField,
    PhoneNumberField,
    EmailField,
    DateTimeField,
    FileField,
    StatusChoiceField
)

from .response_serializers import (
    StandardResponseSerializer,
    PaginatedResponseSerializer,
    ErrorResponseSerializer,
    SuccessResponseSerializer
)

from .composition_mixins import (
    NestedSerializerMixin,
    CompositeValidationMixin,
    DynamicFieldsMixin,
    ReadWriteSerializerMixin
)

# Export all for easy imports
__all__ = [
    # Base serializers
    'BaseModelSerializer',
    'TimestampMixin',
    'UserTrackingMixin', 
    'OrganizationFilterMixin',
    
    # Validation mixins
    'EmailValidationMixin',
    'PhoneValidationMixin',
    'DecimalValidationMixin',
    'DateValidationMixin',
    'FileValidationMixin',
    
    # Field libraries
    'MoneyField',
    'PhoneNumberField',
    'EmailField',
    'DateTimeField',
    'FileField',
    'StatusChoiceField',
    
    # Response serializers
    'StandardResponseSerializer',
    'PaginatedResponseSerializer', 
    'ErrorResponseSerializer',
    'SuccessResponseSerializer',
    
    # Composition mixins
    'NestedSerializerMixin',
    'CompositeValidationMixin',
    'DynamicFieldsMixin',
    'ReadWriteSerializerMixin'
]
