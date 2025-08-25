"""
Standardized Error Response System
Provides consistent, secure error responses across the application
"""

import logging
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, List
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError
from rest_framework import status
from rest_framework.response import Response
import re

logger = logging.getLogger(__name__)

class StandardErrorResponse:
    """
    Standardized error response format that sanitizes sensitive information
    """
    
    # Sensitive patterns to remove from error messages
    SENSITIVE_PATTERNS = [
        r'password["\s]*[:=]["\s]*[^"\s,}]+',  # password fields
        r'token["\s]*[:=]["\s]*[^"\s,}]+',     # token fields
        r'secret["\s]*[:=]["\s]*[^"\s,}]+',    # secret fields
        r'key["\s]*[:=]["\s]*[^"\s,}]+',       # key fields
        r'api_key["\s]*[:=]["\s]*[^"\s,}]+',   # api_key fields
        r'authorization["\s]*[:=]["\s]*[^"\s,}]+',  # authorization headers
        r'cookie["\s]*[:=]["\s]*[^"\s,}]+',    # cookie values
        r'session["\s]*[:=]["\s]*[^"\s,}]+',   # session values
        r'csrf["\s]*[:=]["\s]*[^"\s,}]+',      # csrf tokens
        r'jwt["\s]*[:=]["\s]*[^"\s,}]+',       # jwt tokens
        r'bearer\s+[a-zA-Z0-9\-._~+/]+=*',     # bearer tokens
        r'basic\s+[a-zA-Z0-9+/]+=*',           # basic auth
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # credit card numbers
        r'\b\d{3}-\d{2}-\d{4}\b',              # SSN patterns
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # email addresses (partial)
    ]
    
    # Database error patterns to sanitize
    DB_ERROR_PATTERNS = [
        r'DETAIL:\s*.*',                       # PostgreSQL detail messages
        r'HINT:\s*.*',                         # PostgreSQL hints
        r'CONTEXT:\s*.*',                      # PostgreSQL context
        r'WHERE:\s*.*',                        # PostgreSQL where clause
        r'SQL state:\s*.*',                    # SQL state codes
        r'relation\s+"[^"]*"',                 # table names
        r'column\s+"[^"]*"',                   # column names
        r'constraint\s+"[^"]*"',               # constraint names
    ]
    
    # File path patterns to sanitize
    PATH_PATTERNS = [
        r'/[a-zA-Z0-9_\-./]*\.py',             # Python file paths
        r'/[a-zA-Z0-9_\-./]*\.log',            # Log file paths
        r'/home/[a-zA-Z0-9_\-./]*',            # Home directory paths
        r'/var/[a-zA-Z0-9_\-./]*',             # Var directory paths
        r'/opt/[a-zA-Z0-9_\-./]*',             # Opt directory paths
        r'C:\\[a-zA-Z0-9_\-\\./]*',            # Windows paths
    ]
    
    def __init__(self, 
                 error_code: str, 
                 message: str, 
                 details: Optional[Dict[str, Any]] = None,
                 status_code: int = status.HTTP_400_BAD_REQUEST,
                 request_id: Optional[str] = None):
        """
        Initialize standardized error response
        
        Args:
            error_code: Unique error code for the error type
            message: User-friendly error message
            details: Additional error details (will be sanitized)
            status_code: HTTP status code
            request_id: Request ID for tracking
        """
        self.error_code = error_code
        self.message = self._sanitize_message(message)
        self.details = self._sanitize_details(details or {})
        self.status_code = status_code
        self.request_id = request_id
        self.timestamp = timezone.now().isoformat()
    
    def _sanitize_message(self, message: str) -> str:
        """
        Sanitize error message to remove sensitive information
        """
        if not isinstance(message, str):
            message = str(message)
        
        # Remove sensitive patterns
        for pattern in self.SENSITIVE_PATTERNS:
            message = re.sub(pattern, '[REDACTED]', message, flags=re.IGNORECASE)
        
        # Remove database error details
        for pattern in self.DB_ERROR_PATTERNS:
            message = re.sub(pattern, '[DATABASE_DETAIL_REDACTED]', message, flags=re.IGNORECASE)
        
        # Remove file paths
        for pattern in self.PATH_PATTERNS:
            message = re.sub(pattern, '[PATH_REDACTED]', message)
        
        # Remove stack trace information if not in debug mode
        if not settings.DEBUG:
            # Remove traceback information
            message = re.sub(r'Traceback \(most recent call last\):.*', '[TRACEBACK_REDACTED]', message, flags=re.DOTALL)
            message = re.sub(r'File "[^"]*", line \d+.*', '[FILE_INFO_REDACTED]', message)
        
        return message
    
    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize error details to remove sensitive information
        """
        if not isinstance(details, dict):
            return {}
        
        sanitized = {}
        
        for key, value in details.items():
            # Skip sensitive keys entirely
            if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key', 'auth']):
                sanitized[key] = '[REDACTED]'
                continue
            
            if isinstance(value, str):
                sanitized[key] = self._sanitize_message(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_details(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_message(item) if isinstance(item, str) 
                    else self._sanitize_details(item) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert error response to dictionary format
        """
        response_data = {
            'error': {
                'code': self.error_code,
                'message': self.message,
                'timestamp': self.timestamp
            }
        }
        
        if self.details:
            response_data['error']['details'] = self.details
        
        if self.request_id:
            response_data['error']['request_id'] = self.request_id
        
        # Add debug information only in debug mode
        if settings.DEBUG:
            response_data['error']['debug'] = True
        
        return response_data
    
    def to_response(self) -> Response:
        """
        Convert to Django REST Framework Response with proper renderer setup
        """
        from rest_framework.renderers import JSONRenderer
        
        response = Response(
            data=self.to_dict(),
            status=self.status_code
        )
        
        # Set up renderer to prevent ContentNotRenderedError
        response.accepted_renderer = JSONRenderer()
        response.accepted_media_type = 'application/json'
        response.renderer_context = {}
        
        return response
    
    @classmethod
    def validation_error(cls, message: str = "Validation failed", 
                        details: Optional[Dict[str, Any]] = None,
                        request_id: Optional[str] = None) -> 'StandardErrorResponse':
        """Create validation error response"""
        return cls(
            error_code='VALIDATION_ERROR',
            message=message,
            details=details,
            status_code=status.HTTP_400_BAD_REQUEST,
            request_id=request_id
        )
    
    @classmethod
    def authentication_error(cls, message: str = "Authentication required",
                           request_id: Optional[str] = None) -> 'StandardErrorResponse':
        """Create authentication error response"""
        return cls(
            error_code='AUTHENTICATION_ERROR',
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            request_id=request_id
        )
    
    @classmethod
    def permission_error(cls, message: str = "Permission denied",
                        request_id: Optional[str] = None) -> 'StandardErrorResponse':
        """Create permission error response"""
        return cls(
            error_code='PERMISSION_DENIED',
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            request_id=request_id
        )
    
    @classmethod
    def not_found_error(cls, message: str = "Resource not found",
                       request_id: Optional[str] = None) -> 'StandardErrorResponse':
        """Create not found error response"""
        return cls(
            error_code='NOT_FOUND',
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            request_id=request_id
        )
    
    @classmethod
    def server_error(cls, message: str = "Internal server error",
                    request_id: Optional[str] = None) -> 'StandardErrorResponse':
        """Create server error response"""
        return cls(
            error_code='INTERNAL_ERROR',
            message=message,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            request_id=request_id
        )
    
    @classmethod
    def rate_limit_error(cls, message: str = "Rate limit exceeded",
                        retry_after: Optional[int] = None,
                        request_id: Optional[str] = None) -> 'StandardErrorResponse':
        """Create rate limit error response"""
        details = {}
        if retry_after:
            details['retry_after'] = retry_after
        
        return cls(
            error_code='RATE_LIMIT_EXCEEDED',
            message=message,
            details=details,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            request_id=request_id
        )
    
    @classmethod
    def file_upload_error(cls, message: str = "File upload failed",
                         details: Optional[Dict[str, Any]] = None,
                         request_id: Optional[str] = None) -> 'StandardErrorResponse':
        """Create file upload error response"""
        return cls(
            error_code='FILE_UPLOAD_ERROR',
            message=message,
            details=details,
            status_code=status.HTTP_400_BAD_REQUEST,
            request_id=request_id
        )


class SecureLogger:
    """
    Secure logging utility that sanitizes sensitive information
    """
    
    def __init__(self, logger_name: str):
        self.logger = logging.getLogger(logger_name)
        self.error_response = StandardErrorResponse('', '')  # For sanitization methods
    
    def _sanitize_log_data(self, data: Any) -> Any:
        """
        Sanitize log data to remove sensitive information
        """
        if isinstance(data, str):
            return self.error_response._sanitize_message(data)
        elif isinstance(data, dict):
            return self.error_response._sanitize_details(data)
        elif isinstance(data, list):
            return [self._sanitize_log_data(item) for item in data]
        else:
            return data
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log debug message with sanitization"""
        sanitized_message = self._sanitize_log_data(message)
        sanitized_extra = self._sanitize_log_data(extra) if extra else None
        self.logger.debug(sanitized_message, extra=sanitized_extra)
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log info message with sanitization"""
        sanitized_message = self._sanitize_log_data(message)
        sanitized_extra = self._sanitize_log_data(extra) if extra else None
        self.logger.info(sanitized_message, extra=sanitized_extra)
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log warning message with sanitization"""
        sanitized_message = self._sanitize_log_data(message)
        sanitized_extra = self._sanitize_log_data(extra) if extra else None
        self.logger.warning(sanitized_message, extra=sanitized_extra)
    
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None, exc_info: bool = False):
        """Log error message with sanitization"""
        sanitized_message = self._sanitize_log_data(message)
        sanitized_extra = self._sanitize_log_data(extra) if extra else None
        
        # In production, don't include full exception info
        if not settings.DEBUG and exc_info:
            exc_info = False
            if sanitized_extra is None:
                sanitized_extra = {}
            sanitized_extra['exception_occurred'] = True
        
        self.logger.error(sanitized_message, extra=sanitized_extra, exc_info=exc_info)
    
    def critical(self, message: str, extra: Optional[Dict[str, Any]] = None, exc_info: bool = False):
        """Log critical message with sanitization"""
        sanitized_message = self._sanitize_log_data(message)
        sanitized_extra = self._sanitize_log_data(extra) if extra else None
        
        # In production, don't include full exception info
        if not settings.DEBUG and exc_info:
            exc_info = False
            if sanitized_extra is None:
                sanitized_extra = {}
            sanitized_extra['exception_occurred'] = True
        
        self.logger.critical(sanitized_message, extra=sanitized_extra, exc_info=exc_info)
    
    def log_security_event(self, event_type: str, user_id: Optional[int] = None, 
                          ip_address: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        """
        Log security events with proper sanitization
        """
        log_data = {
            'event_type': event_type,
            'timestamp': timezone.now().isoformat(),
        }
        
        if user_id:
            log_data['user_id'] = user_id
        
        if ip_address:
            log_data['ip_address'] = ip_address
        
        if details:
            log_data['details'] = self._sanitize_log_data(details)
        
        self.info(f"Security event: {event_type}", extra=log_data)
    
    def log_authentication_attempt(self, username: str, success: bool, 
                                 ip_address: str, user_agent: str):
        """
        Log authentication attempts securely
        """
        # Don't log the actual username in case it contains sensitive info
        username_hash = hash(username) if username else None
        
        self.log_security_event(
            event_type='authentication_attempt',
            details={
                'username_hash': username_hash,
                'success': success,
                'ip_address': ip_address,
                'user_agent': user_agent[:200]  # Truncate user agent
            }
        )
    
    def log_permission_denied(self, user_id: int, resource: str, action: str, 
                            ip_address: str):
        """
        Log permission denied events
        """
        self.log_security_event(
            event_type='permission_denied',
            user_id=user_id,
            ip_address=ip_address,
            details={
                'resource': resource,
                'action': action
            }
        )
    
    def log_suspicious_activity(self, activity_type: str, user_id: Optional[int] = None,
                              ip_address: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        """
        Log suspicious activities
        """
        self.log_security_event(
            event_type='suspicious_activity',
            user_id=user_id,
            ip_address=ip_address,
            details={
                'activity_type': activity_type,
                **(details or {})
            }
        )