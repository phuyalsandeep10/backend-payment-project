"""
Validation Mixins - Task 2.4.2

Reusable validation logic for common data types and business rules.
These mixins can be applied to any serializer to add consistent validation.
"""

from rest_framework import serializers
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from decimal import Decimal, InvalidOperation
from datetime import datetime, date
import re
import magic
import logging

logger = logging.getLogger(__name__)


class EmailValidationMixin:
    """
    Mixin for enhanced email validation.
    Task 2.4.2: Consistent email validation across all apps.
    """
    
    def validate_email(self, value):
        """Enhanced email validation"""
        if not value:
            return value
        
        # Basic format validation
        email_validator = EmailValidator()
        try:
            email_validator(value)
        except DjangoValidationError:
            raise serializers.ValidationError("Enter a valid email address.")
        
        # Additional business rules
        self._validate_email_domain(value)
        self._validate_email_uniqueness(value)
        
        return value.lower()  # Normalize to lowercase
    
    def _validate_email_domain(self, email):
        """Validate email domain against business rules"""
        try:
            domain = email.split('@')[1].lower()
            
            # Blocked domains (can be configured)
            blocked_domains = [
                '10minutemail.com', 'tempmail.com', 'guerrillamail.com'
            ]
            
            if domain in blocked_domains:
                raise serializers.ValidationError(
                    "Email from this domain is not allowed."
                )
            
            # Additional domain validation can be added here
            
        except (IndexError, AttributeError):
            raise serializers.ValidationError("Invalid email format.")
    
    def _validate_email_uniqueness(self, email):
        """Validate email uniqueness (override in subclasses if needed)"""
        # This is a placeholder - implement in specific serializers
        pass


class PhoneValidationMixin:
    """
    Mixin for phone number validation.
    Task 2.4.2: Consistent phone validation across all apps.
    """
    
    def validate_phone_number(self, value):
        """Enhanced phone number validation"""
        if not value:
            return value
        
        # Remove common formatting
        cleaned_phone = self._clean_phone_number(value)
        
        # Validate format
        if not self._is_valid_phone_format(cleaned_phone):
            raise serializers.ValidationError(
                "Enter a valid phone number (10-15 digits)."
            )
        
        return cleaned_phone
    
    def validate_contact_number(self, value):
        """Alias for phone number validation"""
        return self.validate_phone_number(value)
    
    def _clean_phone_number(self, phone):
        """Clean phone number formatting"""
        if not phone:
            return phone
        
        # Remove common formatting characters
        cleaned = re.sub(r'[^\d+]', '', phone)
        
        # Handle country codes
        if cleaned.startswith('+'):
            return cleaned
        elif len(cleaned) == 10 and not cleaned.startswith('0'):
            return f"+1{cleaned}"  # Assume US/Canada
        
        return cleaned
    
    def _is_valid_phone_format(self, phone):
        """Check if phone number format is valid"""
        if not phone:
            return True  # Allow empty
        
        # Basic length check (10-15 digits)
        digits_only = re.sub(r'[^\d]', '', phone)
        return 10 <= len(digits_only) <= 15


class DecimalValidationMixin:
    """
    Mixin for decimal/money field validation.
    Task 2.4.2: Consistent financial data validation.
    """
    
    def validate_amount(self, value):
        """Validate monetary amounts"""
        return self._validate_decimal_field(value, 'amount')
    
    def validate_deal_value(self, value):
        """Validate deal value"""
        return self._validate_decimal_field(value, 'deal_value', min_value=Decimal('0.01'))
    
    def validate_received_amount(self, value):
        """Validate received amount"""
        return self._validate_decimal_field(value, 'received_amount', min_value=Decimal('0.00'))
    
    def validate_commission_rate(self, value):
        """Validate commission rate (percentage)"""
        return self._validate_decimal_field(
            value, 'commission_rate', 
            min_value=Decimal('0.00'), 
            max_value=Decimal('100.00')
        )
    
    def _validate_decimal_field(self, value, field_name, min_value=None, max_value=None):
        """Generic decimal field validation"""
        if value is None:
            return value
        
        try:
            # Convert to Decimal for precision
            decimal_value = Decimal(str(value))
            
            # Check for reasonable precision (2 decimal places max for money)
            if decimal_value.as_tuple().exponent < -2:
                raise serializers.ValidationError(
                    f"{field_name} cannot have more than 2 decimal places."
                )
            
            # Min value check
            if min_value is not None and decimal_value < min_value:
                raise serializers.ValidationError(
                    f"{field_name} must be at least {min_value}."
                )
            
            # Max value check
            if max_value is not None and decimal_value > max_value:
                raise serializers.ValidationError(
                    f"{field_name} cannot exceed {max_value}."
                )
            
            return decimal_value
            
        except (InvalidOperation, ValueError):
            raise serializers.ValidationError(f"Enter a valid number for {field_name}.")


class DateValidationMixin:
    """
    Mixin for date and datetime validation.
    Task 2.4.2: Consistent date validation across all apps.
    """
    
    def validate_deal_date(self, value):
        """Validate deal date"""
        return self._validate_date_field(value, 'deal_date', allow_future=True)
    
    def validate_due_date(self, value):
        """Validate due date"""
        return self._validate_date_field(value, 'due_date', allow_future=True, allow_past=False)
    
    def validate_birth_date(self, value):
        """Validate birth date"""
        return self._validate_date_field(value, 'birth_date', allow_future=False)
    
    def validate_payment_date(self, value):
        """Validate payment date"""
        return self._validate_date_field(value, 'payment_date', allow_future=False)
    
    def _validate_date_field(self, value, field_name, allow_future=True, allow_past=True):
        """Generic date field validation"""
        if not value:
            return value
        
        try:
            # Handle both date and datetime objects
            if isinstance(value, str):
                # Try to parse string dates
                try:
                    parsed_date = datetime.strptime(value, '%Y-%m-%d').date()
                except ValueError:
                    try:
                        parsed_date = datetime.strptime(value, '%Y-%m-%d %H:%M:%S').date()
                    except ValueError:
                        raise serializers.ValidationError(f"Invalid date format for {field_name}.")
            elif isinstance(value, datetime):
                parsed_date = value.date()
            elif isinstance(value, date):
                parsed_date = value
            else:
                parsed_date = value
            
            today = date.today()
            
            # Future date check
            if not allow_future and parsed_date > today:
                raise serializers.ValidationError(f"{field_name} cannot be in the future.")
            
            # Past date check
            if not allow_past and parsed_date < today:
                raise serializers.ValidationError(f"{field_name} cannot be in the past.")
            
            # Reasonable date range (not too far in past or future)
            from datetime import timedelta
            if parsed_date < (today - timedelta(days=36500)):  # 100 years ago
                raise serializers.ValidationError(f"{field_name} is too far in the past.")
            
            if parsed_date > (today + timedelta(days=36500)):  # 100 years future
                raise serializers.ValidationError(f"{field_name} is too far in the future.")
            
            return parsed_date
            
        except Exception as e:
            logger.error(f"Date validation error for {field_name}: {e}")
            raise serializers.ValidationError(f"Invalid date for {field_name}.")
    
    def validate_date_range(self, start_date, end_date, start_field='start_date', end_field='end_date'):
        """Validate that start_date <= end_date"""
        if start_date and end_date:
            if start_date > end_date:
                raise serializers.ValidationError({
                    end_field: f"{end_field} must be after {start_field}."
                })
        return start_date, end_date


class FileValidationMixin:
    """
    Mixin for file upload validation.
    Task 2.4.2: Consistent file validation across all apps.
    """
    
    # File size limits (in bytes)
    MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_DOCUMENT_SIZE = 10 * 1024 * 1024  # 10MB
    
    # Allowed file types
    ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp']
    ALLOWED_DOCUMENT_TYPES = [
        'application/pdf', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ]
    
    def validate_profile_picture(self, value):
        """Validate profile picture upload"""
        return self._validate_image_file(value, 'profile_picture')
    
    def validate_document(self, value):
        """Validate document upload"""
        return self._validate_document_file(value, 'document')
    
    def validate_attachment(self, value):
        """Validate general attachment"""
        return self._validate_file(
            value, 'attachment',
            max_size=self.MAX_DOCUMENT_SIZE,
            allowed_types=self.ALLOWED_DOCUMENT_TYPES + self.ALLOWED_IMAGE_TYPES
        )
    
    def _validate_image_file(self, file_obj, field_name):
        """Validate image file"""
        return self._validate_file(
            file_obj, field_name,
            max_size=self.MAX_IMAGE_SIZE,
            allowed_types=self.ALLOWED_IMAGE_TYPES
        )
    
    def _validate_document_file(self, file_obj, field_name):
        """Validate document file"""
        return self._validate_file(
            file_obj, field_name,
            max_size=self.MAX_DOCUMENT_SIZE,
            allowed_types=self.ALLOWED_DOCUMENT_TYPES
        )
    
    def _validate_file(self, file_obj, field_name, max_size, allowed_types):
        """Generic file validation"""
        if not file_obj:
            return file_obj
        
        # Size validation
        if file_obj.size > max_size:
            max_size_mb = max_size / (1024 * 1024)
            raise serializers.ValidationError(
                f"{field_name} file size cannot exceed {max_size_mb:.1f}MB."
            )
        
        # MIME type validation using python-magic
        try:
            file_obj.seek(0)  # Reset file pointer
            mime_type = magic.from_buffer(file_obj.read(1024), mime=True)
            file_obj.seek(0)  # Reset again
            
            if mime_type not in allowed_types:
                allowed_extensions = self._get_extensions_for_types(allowed_types)
                raise serializers.ValidationError(
                    f"{field_name} must be one of: {', '.join(allowed_extensions)}."
                )
            
        except Exception as e:
            logger.warning(f"File type detection failed: {e}")
            # Fall back to extension checking
            if not self._validate_file_extension(file_obj.name, allowed_types):
                allowed_extensions = self._get_extensions_for_types(allowed_types)
                raise serializers.ValidationError(
                    f"{field_name} must be one of: {', '.join(allowed_extensions)}."
                )
        
        # Additional security checks
        self._validate_file_security(file_obj, field_name)
        
        return file_obj
    
    def _get_extensions_for_types(self, mime_types):
        """Get file extensions for MIME types"""
        type_to_ext = {
            'image/jpeg': 'JPG',
            'image/png': 'PNG',
            'image/webp': 'WEBP',
            'application/pdf': 'PDF',
            'application/msword': 'DOC',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'DOCX'
        }
        return [type_to_ext.get(mime_type, mime_type) for mime_type in mime_types]
    
    def _validate_file_extension(self, filename, allowed_types):
        """Validate file extension (fallback method)"""
        if not filename:
            return False
        
        extension = filename.lower().split('.')[-1] if '.' in filename else ''
        
        allowed_extensions = {
            'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
            'png': 'image/png', 'webp': 'image/webp',
            'pdf': 'application/pdf', 'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
        
        return allowed_extensions.get(extension) in allowed_types
    
    def _validate_file_security(self, file_obj, field_name):
        """Additional security validation"""
        try:
            # Check for potentially malicious files
            file_obj.seek(0)
            content = file_obj.read(1024)  # Read first 1KB
            file_obj.seek(0)
            
            # Check for script tags or executable headers
            dangerous_patterns = [
                b'<script', b'<?php', b'#!/bin/', b'MZ\x90\x00'  # PE header
            ]
            
            content_lower = content.lower()
            for pattern in dangerous_patterns:
                if pattern in content_lower:
                    raise serializers.ValidationError(
                        f"{field_name} contains potentially unsafe content."
                    )
                    
        except Exception as e:
            logger.warning(f"File security check failed: {e}")
            # Don't fail validation on security check errors in development
