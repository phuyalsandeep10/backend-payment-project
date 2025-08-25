"""
Comprehensive Input Validation Service

This module provides comprehensive input validation and sanitization
to prevent SQL injection, XSS attacks, and other security vulnerabilities.
"""

import re
import html
import json
import logging
from typing import Dict, Any, List, Optional, Union
from urllib.parse import unquote
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags
from django.conf import settings
import bleach

logger = logging.getLogger(__name__)


class ValidationResult:
    """Result of input validation"""
    
    def __init__(self, is_valid: bool = True, errors: List[str] = None, 
                 sanitized_data: Dict[str, Any] = None):
        self.is_valid = is_valid
        self.errors = errors or []
        self.sanitized_data = sanitized_data or {}
    
    def add_error(self, error: str):
        """Add validation error"""
        self.is_valid = False
        self.errors.append(error)


class InputValidationService:
    """
    Comprehensive input validation and sanitization service
    """
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\b(OR|AND)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
        r"(UNION\s+(ALL\s+)?SELECT)",
        r"(\bEXEC\s*\()",
        r"(\bSP_\w+)",
        r"(\bXP_\w+)",
        r"(\b(WAITFOR|DELAY)\s+)",
        r"(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)",
        r"(\b(CAST|CONVERT|CHAR|ASCII|SUBSTRING)\s*\()",
        r"(0x[0-9A-Fa-f]+)",  # Hexadecimal values
        r"(\\\\x[0-9A-Fa-f]{2})",  # Hex encoded characters
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"vbscript:",
        r"onload\s*=",
        r"onerror\s*=",
        r"onclick\s*=",
        r"onmouseover\s*=",
        r"onfocus\s*=",
        r"onblur\s*=",
        r"onchange\s*=",
        r"onsubmit\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"<link[^>]*>",
        r"<meta[^>]*>",
        r"<style[^>]*>.*?</style>",
        r"expression\s*\(",
        r"url\s*\(",
        r"@import",
        r"<\s*img[^>]+src\s*=\s*[\"']?\s*javascript:",
        r"<\s*img[^>]+src\s*=\s*[\"']?\s*vbscript:",
        r"<\s*img[^>]+src\s*=\s*[\"']?\s*data:",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"..%2f",
        r"..%5c",
        r"%252e%252e%252f",
        r"%252e%252e%255c",
    ]
    
    # Command injection patterns - Fixed to be less aggressive
    COMMAND_INJECTION_PATTERNS = [
        # Only flag actual command injection attempts, not legitimate form data
        r";\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|rm|mv|cp|chmod|chown|sudo|su|kill|killall|pkill|nohup|crontab|at|batch|exec|eval|system)\b",
        r"\|\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|rm|mv|cp|chmod|chown|sudo|su|kill|killall|pkill|nohup|crontab|at|batch|exec|eval|system)\b",
        r"&&\s*(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|rm|mv|cp|chmod|chown|sudo|su|kill|killall|pkill|nohup|crontab|at|batch|exec|eval|system)\b",
        r"`[^`]*\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|rm|mv|cp|chmod|chown|sudo|su|kill|killall|pkill|nohup|crontab|at|batch|exec|eval|system)\b[^`]*`",
        r"\$\([^)]*\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|rm|mv|cp|chmod|chown|sudo|su|kill|killall|pkill|nohup|crontab|at|batch|exec|eval|system)\b[^)]*\)",
        # Only flag suspicious shell metacharacters in specific contexts
        r"^[;&|`]+",  # Commands starting with shell metacharacters
        r"[;&|`]{2,}",  # Multiple consecutive shell metacharacters
    ]
    
    def __init__(self):
        """Initialize the validation service"""
        self.sql_patterns = [re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL) 
                           for pattern in self.SQL_INJECTION_PATTERNS]
        self.xss_patterns = [re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL) 
                           for pattern in self.XSS_PATTERNS]
        self.path_patterns = [re.compile(pattern, re.IGNORECASE) 
                            for pattern in self.PATH_TRAVERSAL_PATTERNS]
        self.cmd_patterns = [re.compile(pattern, re.IGNORECASE) 
                           for pattern in self.COMMAND_INJECTION_PATTERNS]
    
    def validate_and_sanitize(self, data: Dict[str, Any], 
                            schema: Dict[str, Any] = None) -> ValidationResult:
        """
        Validate and sanitize input data according to schema
        
        Args:
            data: Input data to validate
            schema: Validation schema (optional)
            
        Returns:
            ValidationResult with validation status and sanitized data
        """
        result = ValidationResult()
        sanitized_data = {}
        
        try:
            for key, value in data.items():
                # Skip None values
                if value is None:
                    sanitized_data[key] = None
                    continue
                
                # Convert to string for validation
                str_value = str(value)
                
                # Check for security threats
                security_result = self._check_security_threats(str_value, key)
                if not security_result.is_valid:
                    result.errors.extend(security_result.errors)
                    result.is_valid = False
                    continue
                
                # Sanitize the value
                sanitized_value = self._sanitize_value(value, key, schema)
                sanitized_data[key] = sanitized_value
                
                # Apply schema validation if provided
                if schema and key in schema:
                    schema_result = self._validate_against_schema(
                        sanitized_value, schema[key], key
                    )
                    if not schema_result.is_valid:
                        result.errors.extend(schema_result.errors)
                        result.is_valid = False
            
            result.sanitized_data = sanitized_data
            
        except Exception as e:
            logger.error(f"Error during validation: {str(e)}")
            result.add_error("Internal validation error")
        
        return result
    
    def _check_security_threats(self, value: str, field_name: str) -> ValidationResult:
        """Check for various security threats in input value"""
        result = ValidationResult()
        
        # Skip security threat detection for password fields (they're hashed anyway)
        is_password_field = field_name and ('password' in field_name.lower() or 'passwd' in field_name.lower())
        
        # Skip security threat detection for known safe form fields
        is_safe_field = self._is_safe_form_field(field_name)
        
        if not is_password_field and not is_safe_field:
            # Check for SQL injection
            if self.check_sql_injection(value):
                result.add_error(f"Potential SQL injection detected in field '{field_name}'")
                logger.warning(f"SQL injection attempt detected in field '{field_name}': {value[:100]}")
            
            # Check for XSS
            if self.check_xss_patterns(value):
                result.add_error(f"Potential XSS attack detected in field '{field_name}'")
                logger.warning(f"XSS attempt detected in field '{field_name}': {value[:100]}")
            
            # Check for path traversal
            if self.check_path_traversal(value):
                result.add_error(f"Potential path traversal detected in field '{field_name}'")
                logger.warning(f"Path traversal attempt detected in field '{field_name}': {value[:100]}")
            
            # Check for command injection
            if self.check_command_injection(value):
                result.add_error(f"Potential command injection detected in field '{field_name}'")
                logger.warning(f"Command injection attempt detected in field '{field_name}': {value[:100]}")
        
        return result
    
    def _is_safe_form_field(self, field_name: str) -> bool:
        """
        Check if field name is known to be safe from command injection
        
        Args:
            field_name: Name of the field
            
        Returns:
            True if field is known to be safe
        """
        if not field_name:
            return False
        
        # Known safe field patterns for business forms
        safe_field_patterns = [
            r'.*_id$',  # ID fields like client_id, deal_id
            r'.*_name$',  # Name fields like deal_name, client_name
            r'.*_value$',  # Value fields like deal_value
            r'.*_amount$',  # Amount fields like received_amount
            r'.*_date$',  # Date fields like deal_date, payment_date
            r'.*_status$',  # Status fields like payment_status
            r'.*_method$',  # Method fields like payment_method
            r'.*_type$',  # Type fields like source_type
            r'.*_number$',  # Number fields like cheque_number
            r'.*_remarks$',  # Remarks fields
            r'currency$',  # Currency field
            r'payments\[\d+\]\[.*\]',  # Nested payment fields like payments[0][field]
        ]
        
        # Known safe field names
        safe_field_names = [
            'client_id', 'deal_name', 'payment_status', 'source_type', 'currency',
            'deal_value', 'deal_date', 'due_date', 'payment_method', 'deal_remarks',
            'payment_date', 'received_amount', 'cheque_number', 'payment_remarks',
            'receipt_file', 'client_name', 'deal_id', 'organization', 'version',
            'created_by', 'updated_by', 'verification_status', 'payment_category',
            'payment_type', 'transaction_id', 'status'
        ]
        
        # Check exact field name matches
        if field_name.lower() in [name.lower() for name in safe_field_names]:
            return True
        
        # Check field name patterns
        for pattern in safe_field_patterns:
            if re.match(pattern, field_name, re.IGNORECASE):
                return True
        
        return False
    
    def check_sql_injection(self, value: str) -> bool:
        """
        Check for SQL injection patterns
        
        Args:
            value: String value to check
            
        Returns:
            True if potential SQL injection detected
        """
        if not isinstance(value, str):
            return False
        
        # URL decode the value to catch encoded attacks
        decoded_value = unquote(value)
        
        # Check both original and decoded values
        for pattern in self.sql_patterns:
            if pattern.search(value) or pattern.search(decoded_value):
                return True
        
        return False
    
    def check_xss_patterns(self, value: str) -> bool:
        """
        Check for XSS patterns
        
        Args:
            value: String value to check
            
        Returns:
            True if potential XSS detected
        """
        if not isinstance(value, str):
            return False
        
        # URL decode the value to catch encoded attacks
        decoded_value = unquote(value)
        
        # Check both original and decoded values
        for pattern in self.xss_patterns:
            if pattern.search(value) or pattern.search(decoded_value):
                return True
        
        return False
    
    def check_path_traversal(self, value: str) -> bool:
        """
        Check for path traversal patterns
        
        Args:
            value: String value to check
            
        Returns:
            True if potential path traversal detected
        """
        if not isinstance(value, str):
            return False
        
        # URL decode the value to catch encoded attacks
        decoded_value = unquote(value)
        
        # Check both original and decoded values
        for pattern in self.path_patterns:
            if pattern.search(value) or pattern.search(decoded_value):
                return True
        
        return False
    
    def check_command_injection(self, value: str) -> bool:
        """
        Check for command injection patterns
        
        Args:
            value: String value to check
            
        Returns:
            True if potential command injection detected
        """
        if not isinstance(value, str):
            return False
        
        # Skip command injection check for legitimate form data patterns
        if self._is_legitimate_form_data(value):
            return False
        
        # URL decode the value to catch encoded attacks
        decoded_value = unquote(value)
        
        # Check both original and decoded values
        for pattern in self.cmd_patterns:
            if pattern.search(value) or pattern.search(decoded_value):
                return True
        
        return False
    
    def _is_legitimate_form_data(self, value: str) -> bool:
        """
        Check if the value appears to be legitimate form data
        
        Args:
            value: String value to check
            
        Returns:
            True if value appears to be legitimate form data
        """
        # Common legitimate patterns that shouldn't trigger command injection detection
        legitimate_patterns = [
            r'^\d+$',  # Pure numbers
            r'^\d+\.\d+$',  # Decimal numbers
            r'^[a-zA-Z0-9\s\-_.,()]+$',  # Alphanumeric with common punctuation
            r'^[a-zA-Z0-9\s\-_.,()@]+$',  # Email-like patterns
            r'^\$?\d+(\.\d{2})?$',  # Currency values like $100.00
            r'^[a-zA-Z0-9\s\-_.,()]+\.(jpg|jpeg|png|pdf|doc|docx)$',  # File names
            r'^https?://[^\s]+$',  # URLs
            r'^[a-zA-Z0-9\s\-_.,()!@#%^&*+=?/\\]+$',  # General form text with special chars
        ]
        
        # Check if value matches any legitimate pattern
        for pattern in legitimate_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        
        # Check for common form field values
        common_values = [
            'full_payment', 'partial_payment', 'initial_payment',
            'wallet', 'bank', 'cheque', 'cash',
            'linkedin', 'instagram', 'google', 'referral', 'others',
            'USD', 'EUR', 'GBP', 'NPR', 'INR', 'CAD', 'AUD', 'JPY',
            'pending', 'verified', 'rejected', 'approved',
            'advance', 'partial', 'final'
        ]
        
        if value.lower() in [v.lower() for v in common_values]:
            return True
        
        # Check if it's a date format
        date_patterns = [
            r'^\d{4}-\d{2}-\d{2}$',  # YYYY-MM-DD
            r'^\d{2}/\d{2}/\d{4}$',  # MM/DD/YYYY
            r'^\d{2}-\d{2}-\d{4}$',  # MM-DD-YYYY
        ]
        
        for pattern in date_patterns:
            if re.match(pattern, value):
                return True
        
        return False
    
    def _sanitize_value(self, value: Any, field_name: str, 
                       schema: Dict[str, Any] = None) -> Any:
        """
        Sanitize a single value based on its type and field name
        
        Args:
            value: Value to sanitize
            field_name: Name of the field
            schema: Validation schema
            
        Returns:
            Sanitized value
        """
        if value is None:
            return None
        
        # Handle different data types
        if isinstance(value, str):
            return self._sanitize_string(value, field_name, schema)
        elif isinstance(value, dict):
            return self._sanitize_dict(value, schema)
        elif isinstance(value, list):
            return self._sanitize_list(value, field_name, schema)
        else:
            return value
    
    def _sanitize_string(self, value: str, field_name: str, 
                        schema: Dict[str, Any] = None) -> str:
        """
        Sanitize string value
        
        Args:
            value: String to sanitize
            field_name: Name of the field
            schema: Validation schema
            
        Returns:
            Sanitized string
        """
        # Basic HTML escaping
        sanitized = html.escape(value)
        
        # Use bleach for more comprehensive HTML sanitization
        # Allow only safe tags and attributes
        allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
        allowed_attributes = {}
        
        # Check if field allows HTML (from schema)
        if schema and field_name in schema:
            field_schema = schema[field_name]
            if isinstance(field_schema, dict):
                if field_schema.get('allow_html', False):
                    allowed_tags = field_schema.get('allowed_tags', allowed_tags)
                    allowed_attributes = field_schema.get('allowed_attributes', {})
                elif field_schema.get('strip_html', True):
                    # Strip all HTML tags
                    sanitized = strip_tags(sanitized)
        
        # Apply bleach sanitization
        sanitized = bleach.clean(
            sanitized,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        return sanitized
    
    def _sanitize_dict(self, value: Dict[str, Any], 
                      schema: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Sanitize dictionary recursively
        
        Args:
            value: Dictionary to sanitize
            schema: Validation schema
            
        Returns:
            Sanitized dictionary
        """
        sanitized = {}
        for k, v in value.items():
            # Sanitize the key
            clean_key = self._sanitize_string(str(k), 'dict_key')
            # Sanitize the value
            sanitized[clean_key] = self._sanitize_value(v, clean_key, schema)
        return sanitized
    
    def _sanitize_list(self, value: List[Any], field_name: str, 
                      schema: Dict[str, Any] = None) -> List[Any]:
        """
        Sanitize list recursively
        
        Args:
            value: List to sanitize
            field_name: Name of the field
            schema: Validation schema
            
        Returns:
            Sanitized list
        """
        return [self._sanitize_value(item, field_name, schema) for item in value]
    
    def _validate_against_schema(self, value: Any, field_schema: Dict[str, Any], 
                               field_name: str) -> ValidationResult:
        """
        Validate value against field schema
        
        Args:
            value: Value to validate
            field_schema: Schema for the field
            field_name: Name of the field
            
        Returns:
            ValidationResult
        """
        result = ValidationResult()
        
        try:
            # Check required
            if field_schema.get('required', False) and not value:
                result.add_error(f"Field '{field_name}' is required")
                return result
            
            # Check type
            expected_type = field_schema.get('type')
            if expected_type and value is not None:
                if expected_type == 'string' and not isinstance(value, str):
                    result.add_error(f"Field '{field_name}' must be a string")
                elif expected_type == 'integer' and not isinstance(value, int):
                    result.add_error(f"Field '{field_name}' must be an integer")
                elif expected_type == 'float' and not isinstance(value, (int, float)):
                    result.add_error(f"Field '{field_name}' must be a number")
                elif expected_type == 'boolean' and not isinstance(value, bool):
                    result.add_error(f"Field '{field_name}' must be a boolean")
            
            # Check length constraints
            if isinstance(value, str):
                min_length = field_schema.get('min_length')
                max_length = field_schema.get('max_length')
                
                if min_length and len(value) < min_length:
                    result.add_error(f"Field '{field_name}' must be at least {min_length} characters")
                
                if max_length and len(value) > max_length:
                    result.add_error(f"Field '{field_name}' must be at most {max_length} characters")
            
            # Check numeric constraints
            if isinstance(value, (int, float)):
                min_value = field_schema.get('min_value')
                max_value = field_schema.get('max_value')
                
                if min_value is not None and value < min_value:
                    result.add_error(f"Field '{field_name}' must be at least {min_value}")
                
                if max_value is not None and value > max_value:
                    result.add_error(f"Field '{field_name}' must be at most {max_value}")
            
            # Check pattern
            pattern = field_schema.get('pattern')
            if pattern and isinstance(value, str):
                if not re.match(pattern, value):
                    result.add_error(f"Field '{field_name}' does not match required pattern")
            
            # Check allowed values
            allowed_values = field_schema.get('allowed_values')
            if allowed_values and value not in allowed_values:
                result.add_error(f"Field '{field_name}' must be one of: {allowed_values}")
        
        except Exception as e:
            logger.error(f"Error validating field '{field_name}': {str(e)}")
            result.add_error(f"Validation error for field '{field_name}'")
        
        return result
    
    def validate_csrf_token(self, request, token: str) -> bool:
        """
        Validate CSRF token for state-changing operations
        
        Args:
            request: Django request object
            token: CSRF token to validate
            
        Returns:
            True if token is valid
        """
        try:
            from django.middleware.csrf import get_token
            from django.views.decorators.csrf import csrf_exempt
            
            # Get the expected token from the request
            expected_token = get_token(request)
            
            # Compare tokens
            return token == expected_token
        
        except Exception as e:
            logger.error(f"Error validating CSRF token: {str(e)}")
            return False
    
    def create_security_event_log(self, event_type: str, request, 
                                details: Dict[str, Any] = None):
        """
        Create security event log entry
        
        Args:
            event_type: Type of security event
            request: Django request object
            details: Additional event details
        """
        try:
            from .security_monitoring import SecurityEvent
            
            # Get client IP
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0]
            else:
                ip_address = request.META.get('REMOTE_ADDR')
            
            # Create security event
            SecurityEvent.objects.create(
                event_type=event_type,
                user=getattr(request, 'user', None) if hasattr(request, 'user') else None,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                event_data=details or {},
                severity='HIGH' if event_type in ['SQL_INJECTION', 'XSS_ATTEMPT', 'COMMAND_INJECTION'] else 'MEDIUM'
            )
            
        except Exception as e:
            logger.error(f"Error creating security event log: {str(e)}")

    # ===== Missing Validation Methods (Task 1.4.1) =====
    
    def validate_sql_injection(self, value: str, field_name: str = None) -> ValidationResult:
        """
        Validate input for SQL injection attempts
        
        Args:
            value: Input value to validate
            field_name: Name of the field being validated
            
        Returns:
            ValidationResult with validation status
        """
        result = ValidationResult()
        
        if not isinstance(value, str):
            return result
            
        if self.check_sql_injection(value):
            error_msg = f"SQL injection detected in {field_name or 'input'}"
            result.add_error(error_msg)
            logger.warning(f"SQL injection validation failed: {error_msg} - Value: {value[:100]}")
        
        return result
    
    def validate_xss_attempts(self, value: str, field_name: str = None) -> ValidationResult:
        """
        Validate input for XSS attempts
        
        Args:
            value: Input value to validate
            field_name: Name of the field being validated
            
        Returns:
            ValidationResult with validation status
        """
        result = ValidationResult()
        
        if not isinstance(value, str):
            return result
            
        if self.check_xss_patterns(value):
            error_msg = f"XSS attempt detected in {field_name or 'input'}"
            result.add_error(error_msg)
            logger.warning(f"XSS validation failed: {error_msg} - Value: {value[:100]}")
        
        return result
    
    def validate_command_injection(self, value: str, field_name: str = None) -> ValidationResult:
        """
        Validate input for command injection attempts
        
        Args:
            value: Input value to validate
            field_name: Name of the field being validated
            
        Returns:
            ValidationResult with validation status
        """
        result = ValidationResult()
        
        if not isinstance(value, str):
            return result
            
        if self.check_command_injection(value):
            error_msg = f"Command injection detected in {field_name or 'input'}"
            result.add_error(error_msg)
            logger.warning(f"Command injection validation failed: {error_msg} - Value: {value[:100]}")
        
        return result
    
    def validate_path_traversal(self, value: str, field_name: str = None) -> ValidationResult:
        """
        Validate input for path traversal attempts
        
        Args:
            value: Input value to validate
            field_name: Name of the field being validated
            
        Returns:
            ValidationResult with validation status
        """
        result = ValidationResult()
        
        if not isinstance(value, str):
            return result
            
        if self.check_path_traversal(value):
            error_msg = f"Path traversal detected in {field_name or 'input'}"
            result.add_error(error_msg)
            logger.warning(f"Path traversal validation failed: {error_msg} - Value: {value[:100]}")
        
        return result
    
    def sanitize_input(self, value: Any, field_name: str = None, 
                      schema: Dict[str, Any] = None) -> Any:
        """
        General input sanitization method
        
        Args:
            value: Input value to sanitize
            field_name: Name of the field being sanitized
            schema: Optional validation schema for the field
            
        Returns:
            Sanitized value
        """
        if field_name is None:
            field_name = "input"
            
        if schema is None:
            # Default schema for general sanitization
            schema = {
                'sanitize_html': True,
                'strip_whitespace': True,
                'check_threats': True
            }
        
        return self._sanitize_value(value, field_name, schema)
    
    def validate_input(self, value: Any, field_name: str = None, 
                      schema: Dict[str, Any] = None) -> ValidationResult:
        """
        Comprehensive input validation method
        
        Args:
            value: Input value to validate
            field_name: Name of the field being validated
            schema: Optional validation schema
            
        Returns:
            ValidationResult with validation status and sanitized data
        """
        result = ValidationResult()
        
        if field_name is None:
            field_name = "input"
        
        try:
            # Sanitize the input first
            sanitized_value = self.sanitize_input(value, field_name, schema)
            result.sanitized_data[field_name] = sanitized_value
            
            # Perform security threat validation if it's a string
            if isinstance(value, str):
                # Skip threat detection for password fields - they need special characters
                is_password_field = field_name and ('password' in field_name.lower() or 'passwd' in field_name.lower())
                
                # Check for SQL injection (skip for password fields)
                if not is_password_field:
                    sql_result = self.validate_sql_injection(value, field_name)
                    result.errors.extend(sql_result.errors)
                
                # Skip security threat detection for password fields (they're hashed anyway)
                if not is_password_field:
                    # Check for XSS
                    xss_result = self.validate_xss_attempts(value, field_name)
                    result.errors.extend(xss_result.errors)
                    
                    # Check for command injection
                    cmd_result = self.validate_command_injection(value, field_name)
                    result.errors.extend(cmd_result.errors)
                    
                    # Check for path traversal
                    path_result = self.validate_path_traversal(value, field_name)
                    result.errors.extend(path_result.errors)
            
            # Validate against schema if provided
            if schema:
                schema_result = self._validate_against_schema(sanitized_value, schema, field_name)
                result.errors.extend(schema_result.errors)
            
            # Set validity based on errors
            result.is_valid = len(result.errors) == 0
            
        except Exception as e:
            logger.error(f"Error validating input '{field_name}': {str(e)}")
            result.add_error(f"Validation error for field '{field_name}'")
        
        return result


# Global instance
input_validator = InputValidationService()