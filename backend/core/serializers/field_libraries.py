"""
Custom Field Libraries - Task 2.4.2

Reusable custom field implementations for consistent data handling.
These fields provide enhanced functionality beyond standard DRF fields.
"""

from rest_framework import serializers
from decimal import Decimal
from django.utils import timezone
from django.core.exceptions import ValidationError as DjangoValidationError
from typing import Dict, Any, Optional, List
import re
import datetime


class MoneyField(serializers.DecimalField):
    """
    Enhanced decimal field for monetary values.
    Task 2.4.2: Consistent money handling across all apps.
    """
    
    def __init__(self, currency_field=None, **kwargs):
        # Set default money field properties
        kwargs.setdefault('max_digits', 15)
        kwargs.setdefault('decimal_places', 2)
        kwargs.setdefault('min_value', Decimal('0.00'))
        
        self.currency_field = currency_field
        super().__init__(**kwargs)
    
    def to_representation(self, value):
        """Enhanced representation with currency formatting"""
        if value is None:
            return None
        
        # Format as decimal
        formatted_value = super().to_representation(value)
        
        # Add currency context if available
        if self.currency_field and hasattr(self.parent, 'instance'):
            instance = self.parent.instance
            if instance and hasattr(instance, self.currency_field):
                currency = getattr(instance, self.currency_field, 'USD')
                return {
                    'amount': formatted_value,
                    'currency': currency,
                    'formatted': f"{currency} {formatted_value}"
                }
        
        return formatted_value
    
    def validate(self, value):
        """Enhanced validation for monetary values"""
        validated_value = super().validate(value)
        
        if validated_value is not None:
            # Additional business rules for money
            self._validate_money_business_rules(validated_value)
        
        return validated_value
    
    def _validate_money_business_rules(self, value):
        """Validate business rules for monetary values"""
        # Check for extremely large amounts
        if value > Decimal('999999999.99'):
            raise serializers.ValidationError(
                "Amount exceeds maximum allowed value."
            )
        
        # Check for negative amounts in contexts where they're not allowed
        if self.min_value is not None and value < self.min_value:
            raise serializers.ValidationError(
                f"Amount cannot be less than {self.min_value}."
            )


class PhoneNumberField(serializers.CharField):
    """
    Enhanced field for phone number handling.
    Task 2.4.2: Consistent phone number processing.
    """
    
    def __init__(self, **kwargs):
        kwargs.setdefault('max_length', 20)
        super().__init__(**kwargs)
    
    def to_internal_value(self, data):
        """Clean and validate phone number"""
        if not data:
            return data
        
        # Clean the phone number
        cleaned_phone = self._clean_phone_number(str(data))
        
        # Validate format
        if not self._is_valid_phone_format(cleaned_phone):
            raise serializers.ValidationError(
                "Enter a valid phone number (10-15 digits)."
            )
        
        return cleaned_phone
    
    def to_representation(self, value):
        """Format phone number for display"""
        if not value:
            return value
        
        # Format for display (US format as example)
        digits_only = re.sub(r'[^\d]', '', value)
        
        if len(digits_only) == 10:
            return f"({digits_only[:3]}) {digits_only[3:6]}-{digits_only[6:]}"
        elif len(digits_only) == 11 and digits_only.startswith('1'):
            return f"+1 ({digits_only[1:4]}) {digits_only[4:7]}-{digits_only[7:]}"
        else:
            return value  # Return as-is for international numbers
    
    def _clean_phone_number(self, phone):
        """Clean phone number formatting"""
        # Remove common formatting characters
        cleaned = re.sub(r'[^\d+]', '', phone)
        
        # Handle country codes
        if cleaned.startswith('+'):
            return cleaned
        elif len(cleaned) == 10 and not cleaned.startswith('0'):
            return f"+1{cleaned}"  # Assume US/Canada for 10-digit numbers
        
        return cleaned
    
    def _is_valid_phone_format(self, phone):
        """Validate phone number format"""
        if not phone:
            return True
        
        digits_only = re.sub(r'[^\d]', '', phone)
        return 10 <= len(digits_only) <= 15


class EmailField(serializers.EmailField):
    """
    Enhanced email field with additional validation.
    Task 2.4.2: Consistent email handling.
    """
    
    def __init__(self, normalize=True, check_domain=True, **kwargs):
        self.normalize = normalize
        self.check_domain = check_domain
        super().__init__(**kwargs)
    
    def to_internal_value(self, data):
        """Enhanced email processing"""
        email = super().to_internal_value(data)
        
        if self.normalize:
            email = email.lower().strip()
        
        if self.check_domain:
            self._validate_domain(email)
        
        return email
    
    def _validate_domain(self, email):
        """Validate email domain"""
        try:
            domain = email.split('@')[1].lower()
            
            # Check against blocked domains
            blocked_domains = [
                '10minutemail.com', 'tempmail.com', 'guerrillamail.com',
                'mailinator.com', 'throwaway.email'
            ]
            
            if domain in blocked_domains:
                raise serializers.ValidationError(
                    "Email from this domain is not allowed."
                )
                
        except (IndexError, AttributeError):
            raise serializers.ValidationError("Invalid email format.")


class DateTimeField(serializers.DateTimeField):
    """
    Enhanced datetime field with timezone handling.
    Task 2.4.2: Consistent datetime processing.
    """
    
    def __init__(self, auto_timezone=True, **kwargs):
        self.auto_timezone = auto_timezone
        super().__init__(**kwargs)
    
    def to_representation(self, value):
        """Enhanced datetime representation with date object support"""
        if value is None:
            return None
        
        # Handle date objects by converting to datetime
        if isinstance(value, datetime.date) and not isinstance(value, datetime.datetime):
            # Convert date to datetime at midnight
            value = datetime.datetime.combine(value, datetime.time.min)
        
        # Ensure timezone awareness - only for datetime objects
        if self.auto_timezone and isinstance(value, datetime.datetime) and timezone.is_naive(value):
            value = timezone.make_aware(value)
        
        # Standard ISO format
        iso_format = super().to_representation(value)
        
        # Add additional formats for convenience
        return {
            'iso': iso_format,
            'display': value.strftime('%Y-%m-%d %H:%M:%S'),
            'date': value.strftime('%Y-%m-%d'),
            'time': value.strftime('%H:%M:%S'),
            'relative': self._get_relative_time(value),
            'timestamp': int(value.timestamp())
        }
    
    def _get_relative_time(self, dt):
        """Get human-readable relative time"""
        try:
            now = timezone.now()
            diff = now - dt
            
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


class StatusChoiceField(serializers.ChoiceField):
    """
    Enhanced choice field for status values.
    Task 2.4.2: Consistent status handling.
    """
    
    def __init__(self, choices, display_map=None, **kwargs):
        self.display_map = display_map or {}
        super().__init__(choices=choices, **kwargs)
    
    def to_representation(self, value):
        """Enhanced status representation"""
        if value is None:
            return None
        
        # Get the choice display name
        display_name = dict(self.choices).get(value, value)
        
        # Use custom display mapping if provided
        if self.display_map and value in self.display_map:
            display_name = self.display_map[value]
        
        return {
            'value': value,
            'display': display_name,
            'css_class': self._get_status_css_class(value)
        }
    
    def _get_status_css_class(self, status):
        """Get CSS class for status styling"""
        status_classes = {
            'active': 'success',
            'inactive': 'secondary',
            'pending': 'warning',
            'approved': 'success',
            'rejected': 'danger',
            'draft': 'info',
            'completed': 'success',
            'cancelled': 'danger',
            'verified': 'success',
            'unverified': 'warning'
        }
        
        return status_classes.get(status.lower() if isinstance(status, str) else status, 'secondary')


class FileField(serializers.FileField):
    """
    Enhanced file field with validation and metadata.
    Task 2.4.2: Consistent file handling.
    """
    
    def __init__(self, allowed_extensions=None, max_size=None, **kwargs):
        self.allowed_extensions = allowed_extensions or []
        self.max_size = max_size
        super().__init__(**kwargs)
    
    def to_internal_value(self, data):
        """Enhanced file validation"""
        file_obj = super().to_internal_value(data)
        
        # Validate file extension
        if self.allowed_extensions:
            self._validate_extension(file_obj)
        
        # Validate file size
        if self.max_size:
            self._validate_size(file_obj)
        
        return file_obj
    
    def to_representation(self, value):
        """Enhanced file representation with metadata"""
        if not value:
            return None
        
        try:
            return {
                'url': value.url,
                'name': value.name,
                'size': value.size if hasattr(value, 'size') else None,
                'extension': self._get_file_extension(value.name),
                'upload_date': getattr(value, 'upload_date', None)
            }
        except Exception:
            return {'url': str(value), 'name': str(value)}
    
    def _validate_extension(self, file_obj):
        """Validate file extension"""
        if not file_obj.name:
            return
        
        extension = self._get_file_extension(file_obj.name)
        if extension.lower() not in [ext.lower() for ext in self.allowed_extensions]:
            raise serializers.ValidationError(
                f"File extension '{extension}' not allowed. "
                f"Allowed extensions: {', '.join(self.allowed_extensions)}"
            )
    
    def _validate_size(self, file_obj):
        """Validate file size"""
        if hasattr(file_obj, 'size') and file_obj.size > self.max_size:
            max_size_mb = self.max_size / (1024 * 1024)
            raise serializers.ValidationError(
                f"File size exceeds maximum allowed size of {max_size_mb:.1f}MB."
            )
    
    def _get_file_extension(self, filename):
        """Extract file extension"""
        return filename.split('.')[-1] if '.' in filename else ''


class JSONField(serializers.JSONField):
    """
    Enhanced JSON field with validation and structure.
    Task 2.4.2: Consistent JSON data handling.
    """
    
    def __init__(self, schema=None, **kwargs):
        self.schema = schema  # Optional JSON schema for validation
        super().__init__(**kwargs)
    
    def to_internal_value(self, data):
        """Enhanced JSON validation"""
        json_data = super().to_internal_value(data)
        
        if self.schema:
            self._validate_schema(json_data)
        
        return json_data
    
    def _validate_schema(self, data):
        """Validate JSON against schema (placeholder)"""
        # This would integrate with a JSON schema validation library
        # For now, just basic structure validation
        if isinstance(self.schema, dict):
            for required_field in self.schema.get('required', []):
                if required_field not in data:
                    raise serializers.ValidationError(
                        f"Required field '{required_field}' missing from JSON data."
                    )


class DynamicChoiceField(serializers.ChoiceField):
    """
    Choice field with dynamic choices based on context.
    Task 2.4.2: Context-aware choice fields.
    """
    
    def __init__(self, choices_callback=None, **kwargs):
        self.choices_callback = choices_callback
        # Start with empty choices, will be populated dynamically
        super().__init__(choices=[], **kwargs)
    
    def bind(self, field_name, parent):
        """Bind field and update choices based on context"""
        super().bind(field_name, parent)
        
        if self.choices_callback:
            try:
                # Get context from parent serializer
                context = getattr(parent, 'context', {})
                dynamic_choices = self.choices_callback(context)
                self.choices = dynamic_choices
                
                # Update the choice dict for validation
                self._choices = dict(dynamic_choices)
                
            except Exception:
                # Fall back to empty choices if callback fails
                self.choices = []
                self._choices = {}
