"""
Secure Error Handlers

This module provides secure error handling functionality that prevents
information leakage while maintaining proper error logging and responses.

Extracted from error_handling.py for better organization.
"""

import logging
from django.core.exceptions import ValidationError, PermissionDenied
from django.conf import settings
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework.exceptions import (
    AuthenticationFailed, 
    PermissionDenied as DRFPermissionDenied,
    NotFound,
    ValidationError as DRFValidationError,
    Throttled
)

from .standard_responses import StandardErrorResponse

# Security logger
security_logger = logging.getLogger('security')
error_logger = logging.getLogger('django.request')


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
    def handle_file_upload_error(exc: Exception, request=None) -> StandardErrorResponse:
        """Handle file upload errors"""
        # Log file upload error
        if request:
            security_logger.warning(
                f"File upload error from {SecureErrorHandler._get_client_ip(request)}: {type(exc).__name__}"
            )
        
        return StandardErrorResponse(
            error_code='FILE_UPLOAD_ERROR',
            status_code=400
        )
    
    @staticmethod
    def handle_malware_detection(request=None, filename: str = None) -> StandardErrorResponse:
        """Handle malware detection in uploaded files"""
        # Log security incident
        if request:
            security_logger.critical(
                f"MALWARE DETECTED from {SecureErrorHandler._get_client_ip(request)}: {filename or 'unknown file'}"
            )
        
        return StandardErrorResponse(
            error_code='MALWARE_DETECTED',
            status_code=400
        )
    
    @staticmethod
    def handle_csrf_error(exc: Exception, request=None) -> StandardErrorResponse:
        """Handle CSRF errors"""
        # Log CSRF error
        if request:
            security_logger.warning(
                f"CSRF error from {SecureErrorHandler._get_client_ip(request)}: {request.path}"
            )
        
        return StandardErrorResponse(
            error_code='CSRF_ERROR',
            status_code=403
        )
    
    @staticmethod
    def handle_timeout_error(exc: Exception, request=None) -> StandardErrorResponse:
        """Handle timeout errors"""
        return StandardErrorResponse(
            error_code='TIMEOUT_ERROR',
            status_code=408
        )
    
    @staticmethod
    def handle_external_service_error(exc: Exception, request=None) -> StandardErrorResponse:
        """Handle external service errors"""
        # Log external service error
        error_logger.warning(f"External service error: {type(exc).__name__}")
        
        return StandardErrorResponse(
            error_code='EXTERNAL_SERVICE_ERROR',
            status_code=503
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


# Helper functions for common error scenarios
def handle_database_connection_error(request=None):
    """Helper for database connection errors"""
    return SecureErrorHandler.handle_database_error(
        Exception("Database connection failed"), request
    )


def handle_api_rate_limit_exceeded(request=None, wait_time=None):
    """Helper for API rate limiting"""
    from rest_framework.exceptions import Throttled
    exc = Throttled()
    if wait_time:
        exc.wait = wait_time
    return SecureErrorHandler.handle_rate_limit_error(exc, request)


def handle_file_too_large(request=None, max_size=None):
    """Helper for file size validation errors"""
    details = {'max_size': max_size} if max_size else None
    return StandardErrorResponse(
        error_code='FILE_UPLOAD_ERROR',
        message='File size exceeds maximum allowed size',
        details=details,
        status_code=413
    )


def handle_invalid_file_type(request=None, allowed_types=None):
    """Helper for file type validation errors"""
    details = {'allowed_types': allowed_types} if allowed_types else None
    return StandardErrorResponse(
        error_code='FILE_UPLOAD_ERROR',
        message='Invalid file type',
        details=details,
        status_code=400
    )


def handle_network_timeout(request=None, timeout_duration=None):
    """Helper for network timeout errors"""
    details = {'timeout_duration': timeout_duration} if timeout_duration else None
    return StandardErrorResponse(
        error_code='TIMEOUT_ERROR',
        message='Request timed out',
        details=details,
        status_code=408
    )
