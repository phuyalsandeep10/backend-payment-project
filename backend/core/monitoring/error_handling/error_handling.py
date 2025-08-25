"""
Error Handling - Refactored Module

This file serves as the main entry point for error handling functionality,
importing from modular components for better organization.

The original 716-line error_handling.py file has been broken down into:
- standard_responses.py: StandardErrorResponse class for consistent error formatting
- secure_handlers.py: SecureErrorHandler class and custom exception handling
- security_logging.py: SecureLoggingFilter and SecurityEventLogger classes

This refactoring reduces complexity and improves maintainability.
"""

# Import all classes from modular files for backward compatibility
from .standard_responses import StandardErrorResponse

from .secure_handlers import (
    SecureErrorHandler,
    custom_exception_handler,
    handle_database_connection_error,
    handle_api_rate_limit_exceeded,
    handle_file_too_large,
    handle_invalid_file_type,
    handle_network_timeout
)

from .security_logging import (
    SecureLoggingFilter,
    SecurityEventLogger,
    security_event_logger,
    log_security_event,
    log_authentication_attempt,
    log_suspicious_activity
)

# Make all imports available at module level for backward compatibility
__all__ = [
    # Standard responses
    'StandardErrorResponse',
    
    # Secure error handlers
    'SecureErrorHandler',
    'custom_exception_handler',
    
    # Helper functions
    'handle_database_connection_error',
    'handle_api_rate_limit_exceeded',
    'handle_file_too_large',
    'handle_invalid_file_type',
    'handle_network_timeout',
    
    # Security logging
    'SecureLoggingFilter',
    'SecurityEventLogger',
    'security_event_logger',
    'log_security_event',
    'log_authentication_attempt',
    'log_suspicious_activity'
]


# Legacy compatibility - commonly used patterns
def create_error_response(error_code: str, message: str = None, status_code: int = 400, **kwargs):
    """
    Legacy helper function for creating standardized error responses
    """
    return StandardErrorResponse(
        error_code=error_code,
        message=message,
        status_code=status_code,
        **kwargs
    )


def handle_validation_error(exc, request=None):
    """Legacy wrapper for validation error handling"""
    return SecureErrorHandler.handle_validation_error(exc, request)


def handle_authentication_error(exc, request=None):
    """Legacy wrapper for authentication error handling"""
    return SecureErrorHandler.handle_authentication_error(exc, request)


def handle_permission_error(exc, request=None):
    """Legacy wrapper for permission error handling"""
    return SecureErrorHandler.handle_permission_error(exc, request)


def get_client_ip(request):
    """Legacy helper for getting client IP"""
    return SecureErrorHandler._get_client_ip(request)


# Legacy import compatibility
StandardError = StandardErrorResponse  # Alias for backward compatibility


class ErrorContext:
    """
    Context manager for enhanced error handling with automatic logging
    """
    
    def __init__(self, request=None, context_name: str = "operation"):
        self.request = request
        self.context_name = context_name
        self.security_logger = SecurityEventLogger()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            # Log the error with context
            if self.request:
                self.security_logger.log_security_event(
                    request=self.request,
                    event_type='operation_error',
                    event_data={
                        'context': self.context_name,
                        'exception_type': exc_type.__name__,
                        'exception_message': str(exc_val)
                    },
                    severity='medium',
                    description=f"Error in {self.context_name}: {exc_type.__name__}"
                )
        return False  # Don't suppress the exception


# Quick access functions for common error scenarios
def validation_error(message="Validation failed", details=None):
    """Quick validation error response"""
    return StandardErrorResponse('VALIDATION_ERROR', message, details=details, status_code=400)


def authentication_error(message="Authentication required"):
    """Quick authentication error response"""
    return StandardErrorResponse('AUTHENTICATION_ERROR', message, status_code=401)


def permission_error(message="Insufficient permissions"):
    """Quick permission error response"""
    return StandardErrorResponse('PERMISSION_DENIED', message, status_code=403)


def not_found_error(message="Resource not found"):
    """Quick not found error response"""
    return StandardErrorResponse('NOT_FOUND', message, status_code=404)


def rate_limit_error(message="Too many requests", retry_after=None):
    """Quick rate limit error response"""
    details = {'retry_after': retry_after} if retry_after else None
    return StandardErrorResponse('RATE_LIMIT_EXCEEDED', message, details=details, status_code=429)


def internal_error(message="An internal error occurred"):
    """Quick internal error response"""
    return StandardErrorResponse('INTERNAL_ERROR', message, status_code=500)
