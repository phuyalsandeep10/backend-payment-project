"""
Enhanced Error Handling and Response Sanitization
Provides secure error responses that don't expose sensitive information
"""

import logging
import traceback
import re
from typing import Dict, Any, Optional, List
from django.http import JsonResponse
from django.core.exceptions import ValidationError, PermissionDenied
from django.conf import settings
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import (
    AuthenticationFailed, 
    PermissionDenied as DRFPermissionDenied,
    NotFound,
    ValidationError as DRFValidationError,
    Throttled
)

# Security logger
security_logger = logging.getLogger('security')
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
        
        # Remove potential stack trace information
        sanitized = re.sub(r'Traceback \(most recent call last\):.*', '[STACK_TRACE_REDACTED]', 
                          sanitized, flags=re.DOTALL)
        
        # Remove Django debug information
        sanitized = re.sub(r'Django version \d+\.\d+\.\d+.*', '[DEBUG_INFO_REDACTED]', 
                          sanitized, flags=re.DOTALL)
        
        # Limit message length
        if len(sanitized) > 500:
            sanitized = sanitized[:497] + '...'
        
        return sanitized
    
    def _sanitize_details(self, details: Any) -> Any:
        """Sanitize error details to remove sensitive information"""
        if details is None:
            return None
        
        if isinstance(details, dict):
            sanitized = {}
            for key, value in details.items():
                # Skip sensitive keys
                if key.lower() in ['password', 'token', 'secret', 'key', 'private']:
                    continue
                
                sanitized[key] = self._sanitize_details(value)
            return sanitized
        
        elif isinstance(details, list):
            return [self._sanitize_details(item) for item in details]
        
        elif isinstance(details, str):
            return self._sanitize_message(details)
        
        else:
            return details
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON response"""
        response_data = {
            'error': {
                'code': self.error_code,
                'message': self.message,
                'correlation_id': self.correlation_id
            }
        }
        
        if self.details:
            response_data['error']['details'] = self.details
        
        # Add timestamp in production
        if not settings.DEBUG:
            from django.utils import timezone
            response_data['error']['timestamp'] = timezone.now().isoformat()
        
        return response_data
    
    def to_response(self) -> JsonResponse:
        """Convert to Django JsonResponse"""
        return JsonResponse(self.to_dict(), status=self.status_code)


class SecureErrorHandler:
    """
    Secure error handler that prevents information leakage
    """
    
    @staticmethod
    def handle_validation_error(exc: ValidationError, request=None) -> StandardErrorResponse:
        """Handle Django ValidationError"""
        if hasattr(exc, 'message_dict'):
            details = exc.message_dict
        elif hasattr(exc, 'messages'):
            details = list(exc.messages)
        else:
            details = str(exc)
        
        # Log validation error
        if request:
            security_logger.warning(
                f"Validation error from {SecureErrorHandler._get_client_ip(request)}: {str(exc)}"
            )
        
        return StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            details=details,
            status_code=400
        )
    
    @staticmethod
    def handle_authentication_error(exc: Exception, request=None) -> StandardErrorResponse:
        """Handle authentication errors"""
        # Log authentication failure
        if request:
            security_logger.warning(
                f"Authentication failed from {SecureErrorHandler._get_client_ip(request)}: {type(exc).__name__}"
            )
        
        return StandardErrorResponse(
            error_code='AUTHENTICATION_ERROR',
            status_code=401
        )
    
    @staticmethod
    def handle_permission_error(exc: Exception, request=None) -> StandardErrorResponse:
        """Handle permission errors"""
        # Log permission denial
        if request:
            user = getattr(request, 'user', None)
            security_logger.warning(
                f"Permission denied for user {user} from {SecureErrorHandler._get_client_ip(request)}: {request.path}"
            )
        
        return StandardErrorResponse(
            error_code='PERMISSION_DENIED',
            status_code=403
        )
    
    @staticmethod
    def handle_not_found_error(exc: Exception, request=None) -> StandardErrorResponse:
        """Handle not found errors"""
        return StandardErrorResponse(
            error_code='NOT_FOUND',
            status_code=404
        )
    
    @staticmethod
    def handle_rate_limit_error(exc: Throttled, request=None) -> StandardErrorResponse:
        """Handle rate limiting errors"""
        # Log rate limit violation
        if request:
            security_logger.warning(
                f"Rate limit exceeded from {SecureErrorHandler._get_client_ip(request)}: {request.path}"
            )
        
        retry_after = getattr(exc, 'wait', None)
        details = {'retry_after': retry_after} if retry_after else None
        
        return StandardErrorResponse(
            error_code='RATE_LIMIT_EXCEEDED',
            details=details,
            status_code=429
        )
    
    @staticmethod
    def handle_database_error(exc: Exception, request=None) -> StandardErrorResponse:
        """Handle database errors"""
        # Log database error (without sensitive details)
        error_logger.error(f"Database error: {type(exc).__name__}")
        
        return StandardErrorResponse(
            error_code='DATABASE_ERROR',
            status_code=500
        )
    
    @staticmethod
    def handle_generic_error(exc: Exception, request=None) -> StandardErrorResponse:
        """Handle generic errors"""
        # Log generic error
        error_logger.error(f"Unhandled error: {type(exc).__name__}: {str(exc)}")
        
        # In debug mode, include more details
        details = None
        if settings.DEBUG:
            details = {
                'exception_type': type(exc).__name__,
                'exception_message': str(exc)
            }
        
        return StandardErrorResponse(
            error_code='INTERNAL_ERROR',
            details=details,
            status_code=500
        )
    
    @staticmethod
    def _get_client_ip(request) -> str:
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip


def custom_exception_handler(exc, context):
    """
    Custom DRF exception handler with secure error responses
    """
    request = context.get('request')
    
    # Handle specific exception types
    if isinstance(exc, ValidationError):
        error_response = SecureErrorHandler.handle_validation_error(exc, request)
    elif isinstance(exc, DRFValidationError):
        error_response = SecureErrorHandler.handle_validation_error(exc, request)
    elif isinstance(exc, (AuthenticationFailed,)):
        error_response = SecureErrorHandler.handle_authentication_error(exc, request)
    elif isinstance(exc, (PermissionDenied, DRFPermissionDenied)):
        error_response = SecureErrorHandler.handle_permission_error(exc, request)
    elif isinstance(exc, NotFound):
        error_response = SecureErrorHandler.handle_not_found_error(exc, request)
    elif isinstance(exc, Throttled):
        error_response = SecureErrorHandler.handle_rate_limit_error(exc, request)
    else:
        # Try default DRF handler first
        response = exception_handler(exc, context)
        if response is not None:
            # Sanitize DRF response
            sanitized_data = StandardErrorResponse(
                error_code='VALIDATION_ERROR' if response.status_code == 400 else 'INTERNAL_ERROR',
                message=str(response.data) if response.data else None,
                status_code=response.status_code
            )
            return Response(sanitized_data.to_dict(), status=response.status_code)
        else:
            # Handle as generic error
            error_response = SecureErrorHandler.handle_generic_error(exc, request)
    
    return Response(error_response.to_dict(), status=error_response.status_code)


class SecureLoggingFilter(logging.Filter):
    """
    Logging filter to sanitize log messages and prevent sensitive data leakage
    """
    
    # Sensitive patterns to remove from logs
    SENSITIVE_PATTERNS = [
        # Passwords and secrets
        (r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'password=***'),
        (r'secret["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'secret=***'),
        (r'token["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'token=***'),
        (r'key["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'key=***'),
        
        # API keys
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]+', 'api_key=***'),
        
        # Database URLs
        (r'postgresql://[^@]+@[^/]+/\w+', 'postgresql://***:***@***/***'),
        (r'mysql://[^@]+@[^/]+/\w+', 'mysql://***:***@***/***'),
        
        # Email addresses (in some contexts)
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***'),
        
        # Credit card numbers
        (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '****-****-****-****'),
        
        # Social security numbers
        (r'\b\d{3}-\d{2}-\d{4}\b', '***-**-****'),
        
        # Phone numbers (in some contexts)
        (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '***-***-****'),
    ]
    
    def filter(self, record):
        """Filter and sanitize log record"""
        if hasattr(record, 'msg') and record.msg:
            # Sanitize the log message
            sanitized_msg = str(record.msg)
            
            for pattern, replacement in self.SENSITIVE_PATTERNS:
                sanitized_msg = re.sub(pattern, replacement, sanitized_msg, flags=re.IGNORECASE)
            
            record.msg = sanitized_msg
        
        # Sanitize arguments
        if hasattr(record, 'args') and record.args:
            sanitized_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    sanitized_arg = arg
                    for pattern, replacement in self.SENSITIVE_PATTERNS:
                        sanitized_arg = re.sub(pattern, replacement, sanitized_arg, flags=re.IGNORECASE)
                    sanitized_args.append(sanitized_arg)
                else:
                    sanitized_args.append(arg)
            record.args = tuple(sanitized_args)
        
        return True


class SecurityEventLogger:
    """
    Specialized logger for security events with structured logging
    """
    
    def __init__(self):
        self.logger = logging.getLogger('security')
    
    def log_authentication_attempt(self, request, user_identifier: str, success: bool, 
                                 failure_reason: str = None):
        """Log authentication attempt"""
        event_data = {
            'event_type': 'authentication_attempt',
            'user_identifier': user_identifier,
            'success': success,
            'ip_address': self._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', 'unknown'),
            'path': request.path,
        }
        
        if not success and failure_reason:
            event_data['failure_reason'] = failure_reason
        
        level = logging.INFO if success else logging.WARNING
        self.logger.log(level, f"Authentication {'successful' if success else 'failed'}", extra=event_data)
    
    def log_permission_denied(self, request, user, resource: str, action: str):
        """Log permission denied event"""
        event_data = {
            'event_type': 'permission_denied',
            'user_id': getattr(user, 'id', None),
            'user_email': getattr(user, 'email', 'anonymous'),
            'resource': resource,
            'action': action,
            'ip_address': self._get_client_ip(request),
            'path': request.path,
        }
        
        self.logger.warning("Permission denied", extra=event_data)
    
    def log_suspicious_activity(self, request, activity_type: str, details: Dict[str, Any]):
        """Log suspicious activity"""
        event_data = {
            'event_type': 'suspicious_activity',
            'activity_type': activity_type,
            'ip_address': self._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', 'unknown'),
            'path': request.path,
            'details': details,
        }
        
        user = getattr(request, 'user', None)
        if user and user.is_authenticated:
            event_data['user_id'] = user.id
            event_data['user_email'] = user.email
        
        self.logger.error("Suspicious activity detected", extra=event_data)
    
    def log_file_upload_threat(self, request, filename: str, threat_type: str, details: str):
        """Log file upload threat detection"""
        event_data = {
            'event_type': 'file_upload_threat',
            'filename': filename,
            'threat_type': threat_type,
            'details': details,
            'ip_address': self._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', 'unknown'),
        }
        
        user = getattr(request, 'user', None)
        if user and user.is_authenticated:
            event_data['user_id'] = user.id
            event_data['user_email'] = user.email
        
        self.logger.error("File upload threat detected", extra=event_data)
    
    def log_rate_limit_exceeded(self, request, limit_type: str, limit_value: int):
        """Log rate limit exceeded event"""
        event_data = {
            'event_type': 'rate_limit_exceeded',
            'limit_type': limit_type,
            'limit_value': limit_value,
            'ip_address': self._get_client_ip(request),
            'path': request.path,
        }
        
        self.logger.warning("Rate limit exceeded", extra=event_data)
    
    def _get_client_ip(self, request) -> str:
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip


# Global instances
secure_error_handler = SecureErrorHandler()
security_event_logger = SecurityEventLogger()