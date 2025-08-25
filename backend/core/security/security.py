"""
Comprehensive Input Validation and Security Service
Implements security measures to prevent injection attacks, XSS, and other vulnerabilities
"""

import re
import html
import logging
from typing import Dict, Any, List, Optional, Union
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags
from django.conf import settings
import bleach

# Security logger
security_logger = logging.getLogger('security')

class InputValidationService:
    """
    Comprehensive input validation service to prevent security vulnerabilities
    """
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)',
        r'(--|#|/\*|\*/)',
        r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
        r'(\b(OR|AND)\s+[\'"]?\w+[\'"]?\s*=\s*[\'"]?\w+[\'"]?)',
        r'(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)',
        r'(\bxp_cmdshell\b|\bsp_executesql\b)',
        r'(\bUNION\s+(ALL\s+)?SELECT\b)',
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'onfocus\s*=',
        r'onblur\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<link[^>]*>',
        r'<meta[^>]*>',
        r'data:text/html',
        r'data:application/javascript',
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./+',
        r'\.\.\\+',
        r'%2e%2e%2f',
        r'%2e%2e\\',
        r'\.\.%2f',
        r'\.\.%5c',
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r'[;&|`$(){}[\]<>]',
        r'\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp)\b',
        r'(\|\s*\w+|\&\&\s*\w+|\;\s*\w+)',
    ]
    
    # Allowed HTML tags for rich text (very restrictive)
    ALLOWED_HTML_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
    ]
    
    ALLOWED_HTML_ATTRIBUTES = {
        '*': ['class'],
    }
    
    def __init__(self):
        self.sql_regex = re.compile('|'.join(self.SQL_INJECTION_PATTERNS), re.IGNORECASE | re.MULTILINE)
        self.xss_regex = re.compile('|'.join(self.XSS_PATTERNS), re.IGNORECASE | re.MULTILINE)
        self.path_regex = re.compile('|'.join(self.PATH_TRAVERSAL_PATTERNS), re.IGNORECASE)
        self.command_regex = re.compile('|'.join(self.COMMAND_INJECTION_PATTERNS), re.IGNORECASE)
    
    def validate_and_sanitize(self, data: Dict[str, Any], schema: Dict[str, Dict] = None) -> Dict[str, Any]:
        """
        Validate and sanitize input data according to schema
        
        Args:
            data: Input data to validate
            schema: Validation schema with field rules
            
        Returns:
            Sanitized data dictionary
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(data, dict):
            raise ValidationError("Input data must be a dictionary")
        
        sanitized_data = {}
        validation_errors = {}
        
        for field, value in data.items():
            try:
                # Get field schema if provided
                field_schema = schema.get(field, {}) if schema else {}
                
                # Sanitize the value
                sanitized_value = self._sanitize_value(value, field_schema)
                
                # Validate the sanitized value
                self._validate_value(sanitized_value, field, field_schema)
                
                sanitized_data[field] = sanitized_value
                
            except ValidationError as e:
                validation_errors[field] = str(e)
                security_logger.warning(f"Validation failed for field '{field}': {str(e)}")
        
        if validation_errors:
            raise ValidationError(validation_errors)
        
        return sanitized_data
    
    def _sanitize_value(self, value: Any, field_schema: Dict) -> Any:
        """Sanitize a single value based on its type and schema"""
        if value is None:
            return value
        
        field_type = field_schema.get('type', 'string')
        allow_html = field_schema.get('allow_html', False)
        
        if isinstance(value, str):
            # Basic string sanitization
            value = value.strip()
            
            if allow_html:
                # Sanitize HTML but allow safe tags
                value = bleach.clean(
                    value,
                    tags=self.ALLOWED_HTML_TAGS,
                    attributes=self.ALLOWED_HTML_ATTRIBUTES,
                    strip=True
                )
            else:
                # Strip all HTML tags
                value = strip_tags(value)
                # HTML encode special characters
                value = html.escape(value)
            
            # Remove null bytes and control characters
            value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
            
        elif isinstance(value, list):
            # Recursively sanitize list items
            value = [self._sanitize_value(item, field_schema) for item in value]
            
        elif isinstance(value, dict):
            # Recursively sanitize dictionary values
            value = {k: self._sanitize_value(v, field_schema) for k, v in value.items()}
        
        return value
    
    def _validate_value(self, value: Any, field_name: str, field_schema: Dict):
        """Validate a sanitized value for security threats"""
        if value is None:
            return
        
        if isinstance(value, str):
            # Check for SQL injection
            if self.check_sql_injection(value):
                security_logger.error(f"SQL injection attempt detected in field '{field_name}': {value[:100]}")
                raise ValidationError(f"Invalid characters detected in {field_name}")
            
            # Check for XSS
            if self.check_xss_patterns(value):
                security_logger.error(f"XSS attempt detected in field '{field_name}': {value[:100]}")
                raise ValidationError(f"Invalid content detected in {field_name}")
            
            # Check for path traversal
            if self.check_path_traversal(value):
                security_logger.error(f"Path traversal attempt detected in field '{field_name}': {value[:100]}")
                raise ValidationError(f"Invalid path detected in {field_name}")
            
            # Check for command injection
            if field_schema.get('check_commands', True) and self.check_command_injection(value):
                security_logger.error(f"Command injection attempt detected in field '{field_name}': {value[:100]}")
                raise ValidationError(f"Invalid characters detected in {field_name}")
            
            # Length validation
            max_length = field_schema.get('max_length')
            if max_length and len(value) > max_length:
                raise ValidationError(f"{field_name} exceeds maximum length of {max_length}")
            
            min_length = field_schema.get('min_length', 0)
            if len(value) < min_length:
                raise ValidationError(f"{field_name} must be at least {min_length} characters")
        
        elif isinstance(value, (list, dict)):
            # Recursively validate nested structures
            if isinstance(value, list):
                for i, item in enumerate(value):
                    self._validate_value(item, f"{field_name}[{i}]", field_schema)
            else:
                for key, val in value.items():
                    self._validate_value(val, f"{field_name}.{key}", field_schema)
    
    def check_sql_injection(self, value: str) -> bool:
        """Check for SQL injection patterns"""
        if not isinstance(value, str):
            return False
        return bool(self.sql_regex.search(value))
    
    def check_xss_patterns(self, value: str) -> bool:
        """Check for XSS patterns"""
        if not isinstance(value, str):
            return False
        return bool(self.xss_regex.search(value))
    
    def check_path_traversal(self, value: str) -> bool:
        """Check for path traversal patterns"""
        if not isinstance(value, str):
            return False
        return bool(self.path_regex.search(value))
    
    def check_command_injection(self, value: str) -> bool:
        """Check for command injection patterns"""
        if not isinstance(value, str):
            return False
        return bool(self.command_regex.search(value))
    
    def validate_email_field(self, email: str) -> str:
        """Validate and sanitize email field"""
        if not email:
            raise ValidationError("Email is required")
        
        # Basic sanitization
        email = email.strip().lower()
        
        # Check for injection attempts
        if self.check_sql_injection(email) or self.check_xss_patterns(email):
            security_logger.error(f"Malicious email detected: {email}")
            raise ValidationError("Invalid email format")
        
        # Django's email validation
        from django.core.validators import validate_email
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError("Invalid email format")
        
        return email
    
    def validate_phone_field(self, phone: str) -> str:
        """Validate and sanitize phone field"""
        if not phone:
            return phone
        
        # Remove all non-digit characters except + and spaces
        phone = re.sub(r'[^\d\+\s\-\(\)]', '', phone.strip())
        
        # Check for injection attempts
        if self.check_sql_injection(phone) or self.check_command_injection(phone):
            security_logger.error(f"Malicious phone number detected: {phone}")
            raise ValidationError("Invalid phone number format")
        
        return phone
    
    def validate_financial_field(self, amount: Union[str, float, int]) -> str:
        """Validate financial amounts"""
        if amount is None:
            return amount
        
        # Convert to string for validation
        amount_str = str(amount).strip()
        
        # Check for injection attempts
        if self.check_sql_injection(amount_str) or self.check_command_injection(amount_str):
            security_logger.error(f"Malicious amount detected: {amount_str}")
            raise ValidationError("Invalid amount format")
        
        # Validate numeric format
        if not re.match(r'^\d+(\.\d{1,4})?$', amount_str):
            raise ValidationError("Amount must be a valid number with up to 4 decimal places")
        
        return amount_str


class CSRFProtectionService:
    """
    CSRF protection service for state-changing operations
    """
    
    @staticmethod
    def validate_csrf_token(request):
        """Validate CSRF token for state-changing operations"""
        from django.middleware.csrf import get_token
        from django.views.decorators.csrf import csrf_exempt
        
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            # Get CSRF token from header or form data
            csrf_token = (
                request.META.get('HTTP_X_CSRFTOKEN') or
                request.META.get('HTTP_X_CSRF_TOKEN') or
                request.POST.get('csrfmiddlewaretoken')
            )
            
            if not csrf_token:
                security_logger.warning(f"Missing CSRF token for {request.method} {request.path}")
                raise ValidationError("CSRF token missing")
            
            # Validate token
            expected_token = get_token(request)
            if csrf_token != expected_token:
                security_logger.error(f"Invalid CSRF token for {request.method} {request.path}")
                raise ValidationError("CSRF token invalid")
    
    @staticmethod
    def get_csrf_token(request):
        """Get CSRF token for client"""
        from django.middleware.csrf import get_token
        return get_token(request)


# Global instance
input_validator = InputValidationService()
csrf_protection = CSRFProtectionService()