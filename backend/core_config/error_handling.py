"""
Error Handling - Compatibility Layer

Error handling functionality has been moved to core.monitoring.error_handling
This file provides backward compatibility imports.
"""

# Import all error handling functionality from new location
from core.monitoring.error_handling.error_handling import (
    StandardErrorResponse,
    SecureErrorHandler,
    custom_exception_handler,
    handle_database_connection_error,
    handle_api_rate_limit_exceeded,
    handle_file_too_large,
    handle_invalid_file_type,
    handle_network_timeout,
    SecureLoggingFilter,
    SecurityEventLogger,
    security_event_logger,
    log_security_event,
    log_authentication_attempt,
    log_suspicious_activity
)

from core.monitoring.error_handling.global_exception_handler import (
    global_exception_handler
)

from core.monitoring.error_handling.emergency_response_system import (
    EmergencyResponseSystem
)

# Make all imports available at module level for backward compatibility  
__all__ = [
    'StandardErrorResponse',
    'SecureErrorHandler', 
    'custom_exception_handler',
    'global_exception_handler',
    'EmergencyResponseSystem',
    'handle_database_connection_error',
    'handle_api_rate_limit_exceeded', 
    'handle_file_too_large',
    'handle_invalid_file_type',
    'handle_network_timeout',
    'SecureLoggingFilter',
    'SecurityEventLogger',
    'security_event_logger',
    'log_security_event',
    'log_authentication_attempt',
    'log_suspicious_activity'
]

