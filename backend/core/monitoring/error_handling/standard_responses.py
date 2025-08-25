"""
Standard Error Responses

This module provides standardized error response formatting that prevents
information leakage while maintaining consistent error handling.

Extracted from error_handling.py for better organization.
"""

import logging
import re
from typing import Dict, Any, Optional

# Error logger
error_logger = logging.getLogger('django.request')


class StandardErrorResponse:
    """
    Standardized error response format that prevents information leakage
    """
    
    # Error codes and their safe messages
    ERROR_CODES = {
        'VALIDATION_ERROR': 'Input validation failed',
        'AUTHENTICATION_ERROR': 'Authentication required',
        'PERMISSION_DENIED': 'Insufficient permissions',
        'NOT_FOUND': 'Resource not found',
        'RATE_LIMIT_EXCEEDED': 'Too many requests',
        'FILE_UPLOAD_ERROR': 'File upload failed',
        'DATABASE_ERROR': 'Database operation failed',
        'EXTERNAL_SERVICE_ERROR': 'External service unavailable',
        'INTERNAL_ERROR': 'An internal error occurred',
        'MALWARE_DETECTED': 'File contains malicious content',
        'CSRF_ERROR': 'CSRF token validation failed',
        'TIMEOUT_ERROR': 'Request timeout',
        'NETWORK_ERROR': 'Network error occurred',
    }
    
    # Sensitive patterns to remove from error messages
    SENSITIVE_PATTERNS = [
        # Database connection strings
        r'postgresql://[^@]+@[^/]+/\w+',
        r'mysql://[^@]+@[^/]+/\w+',
        r'sqlite:///[^\s]+',
        
        # File paths
        r'/home/[^/]+/[^\s]+',
        r'/var/[^\s]+',
        r'/etc/[^\s]+',
        r'C:\\[^\s]+',
        
        # API keys and tokens
        r'[Aa]pi[_-]?[Kk]ey["\']?\s*[:=]\s*["\']?[\w-]+',
        r'[Tt]oken["\']?\s*[:=]\s*["\']?[\w.-]+',
        r'[Ss]ecret["\']?\s*[:=]\s*["\']?[\w-]+',
        
        # Email addresses in error messages
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        
        # IP addresses
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        
        # Stack trace file paths
        r'File "[^"]*"',
        r'line \d+',
        
        # SQL query fragments
        r'SELECT\s+[^;]+;?',
        r'INSERT\s+INTO\s+[^;]+;?',
        r'UPDATE\s+[^;]+;?',
        r'DELETE\s+FROM\s+[^;]+;?',
        
        # Environment variables
        r'[A-Z_]+=[^\s]+',
    ]
    
    def __init__(self, error_code: str, message: str = None, details: Any = None, 
                 status_code: int = 400, correlation_id: str = None):
        """
        Initialize standardized error response
        
        Args:
            error_code: Standard error code
            message: Custom error message (will be sanitized)
            details: Error details (will be sanitized)
            status_code: HTTP status code
            correlation_id: Unique identifier for error tracking
        """
        self.error_code = error_code
        self.status_code = status_code
        self.correlation_id = correlation_id or self._generate_correlation_id()
        
        # Use safe message if no custom message provided
        if message is None:
            message = self.ERROR_CODES.get(error_code, 'An error occurred')
        
        # Sanitize message and details
        self.message = self._sanitize_message(message)
        self.details = self._sanitize_details(details)
    
    def _generate_correlation_id(self) -> str:
        """Generate unique correlation ID for error tracking"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _sanitize_message(self, message: str) -> str:
        """Sanitize error message to remove sensitive information"""
        if not isinstance(message, str):
            return str(message)
        
        sanitized = message
        
        # Remove sensitive patterns
        for pattern in self.SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
        
        # Remove Django/Python internals from error messages
        sanitized = self._remove_internal_paths(sanitized)
        
        return sanitized
    
    def _sanitize_details(self, details: Any) -> Any:
        """Sanitize error details"""
        if details is None:
            return None
        
        if isinstance(details, str):
            return self._sanitize_message(details)
        
        elif isinstance(details, dict):
            sanitized_dict = {}
            for key, value in details.items():
                # Sanitize both keys and values
                sanitized_key = self._sanitize_message(str(key))
                sanitized_value = self._sanitize_details(value)
                sanitized_dict[sanitized_key] = sanitized_value
            return sanitized_dict
        
        elif isinstance(details, list):
            return [self._sanitize_details(item) for item in details]
        
        else:
            return self._sanitize_message(str(details))
    
    def _remove_internal_paths(self, message: str) -> str:
        """Remove internal Django/Python paths from error messages"""
        # Common internal patterns to remove
        internal_patterns = [
            r'/usr/local/lib/python[\d.]+/site-packages/[^\s]+',
            r'/opt/[^\s]+',
            r'/Library/[^\s]+',
            r'django/[^\s]+',
            r'site-packages/[^\s]+',
        ]
        
        sanitized = message
        for pattern in internal_patterns:
            sanitized = re.sub(pattern, '[SYSTEM_PATH]', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        response_data = {
            'error': {
                'code': self.error_code,
                'message': self.message,
                'correlation_id': self.correlation_id
            }
        }
        
        if self.details is not None:
            response_data['error']['details'] = self.details
        
        # Add timestamp for tracking
        from django.utils import timezone
        response_data['timestamp'] = timezone.now().isoformat()
        
        return response_data
    
    def to_json_response(self):
        """Convert to Django JsonResponse"""
        from django.http import JsonResponse
        return JsonResponse(self.to_dict(), status=self.status_code)
    
    def to_drf_response(self):
        """Convert to DRF Response"""
        from rest_framework.response import Response
        return Response(self.to_dict(), status=self.status_code)
    
    @classmethod
    def from_exception(cls, exc: Exception, error_code: str = None, 
                      status_code: int = None, request=None):
        """Create StandardErrorResponse from an exception"""
        
        # Auto-detect error code if not provided
        if error_code is None:
            error_code = cls._detect_error_code(exc)
        
        # Auto-detect status code if not provided
        if status_code is None:
            status_code = cls._detect_status_code(exc)
        
        # Get sanitized message from exception
        message = str(exc) if str(exc) else cls.ERROR_CODES.get(error_code, 'An error occurred')
        
        return cls(
            error_code=error_code,
            message=message,
            status_code=status_code
        )
    
    @staticmethod
    def _detect_error_code(exc: Exception) -> str:
        """Auto-detect appropriate error code from exception type"""
        from django.core.exceptions import ValidationError, PermissionDenied
        from rest_framework.exceptions import (
            AuthenticationFailed, 
            PermissionDenied as DRFPermissionDenied,
            NotFound,
            ValidationError as DRFValidationError,
            Throttled
        )
        
        if isinstance(exc, (ValidationError, DRFValidationError)):
            return 'VALIDATION_ERROR'
        elif isinstance(exc, (AuthenticationFailed,)):
            return 'AUTHENTICATION_ERROR'
        elif isinstance(exc, (PermissionDenied, DRFPermissionDenied)):
            return 'PERMISSION_DENIED'
        elif isinstance(exc, NotFound):
            return 'NOT_FOUND'
        elif isinstance(exc, Throttled):
            return 'RATE_LIMIT_EXCEEDED'
        else:
            return 'INTERNAL_ERROR'
    
    @staticmethod
    def _detect_status_code(exc: Exception) -> int:
        """Auto-detect appropriate HTTP status code from exception type"""
        from django.core.exceptions import ValidationError, PermissionDenied
        from rest_framework.exceptions import (
            AuthenticationFailed, 
            PermissionDenied as DRFPermissionDenied,
            NotFound,
            ValidationError as DRFValidationError,
            Throttled
        )
        
        if isinstance(exc, (ValidationError, DRFValidationError)):
            return 400
        elif isinstance(exc, AuthenticationFailed):
            return 401
        elif isinstance(exc, (PermissionDenied, DRFPermissionDenied)):
            return 403
        elif isinstance(exc, NotFound):
            return 404
        elif isinstance(exc, Throttled):
            return 429
        else:
            return 500
