"""
Enhanced Error Logging and Monitoring System for PRS Backend

This module provides comprehensive error tracking, structured logging,
and monitoring capabilities for the Payment Receiving System.

Components:
- StructuredLogger: Enhanced logging with correlation and context
- ErrorCorrelationTracker: Track and correlate error patterns
- ErrorMonitoringDashboard: Web-based error monitoring interface
- Enhanced middleware: Exception, performance, and security monitoring
- Integration utilities: Easy setup and configuration

Usage:
    # Basic structured logging
    from core.logging import StructuredLogger, EventType
    
    logger = StructuredLogger('my_module')
    logger.info(EventType.USER_LOGIN, "User logged in successfully", user_id=123)
    
    # Error correlation
    from core.logging import track_error
    
    try:
        # Some operation
        pass
    except Exception as e:
        track_error(e, user_id=123, additional_context={})
    
    # Business event logging
    from core.logging import log_business_event
    
    log_business_event('deal_created', entity_id=456, user_id=123)
"""

from .structured_logger import (
    StructuredLogger,
    EventType,
    LogLevel,
    LogContext,
    LogEvent,
    CorrelationMiddleware,
    structured_logger,
    set_user_context,
    set_request_context,
    get_correlation_id,
    with_correlation_id
)

from .error_correlation import (
    ErrorCorrelationTracker,
    ErrorSignature,
    ErrorOccurrence, 
    ErrorCluster,
    ErrorPattern,
    error_tracker,
    track_error,
    get_error_summary,
    get_error_cluster
)

from .error_monitoring_dashboard import (
    ErrorDashboardData,
    ErrorDashboardView,
    ErrorDashboardAPIView,
    ErrorDetailView,
    ErrorActionView,
    get_error_monitoring_urls
)

from .enhanced_exception_middleware import (
    EnhancedExceptionMiddleware,
    PerformanceMonitoringMiddleware,
    SecurityEventMiddleware
)

from .integration import (
    LoggingSystemIntegrator,
    integrate_with_settings,
    get_admin_urls,
    setup_development_logging,
    setup_production_logging,
    log_business_event,
    log_security_event,
    log_performance_issue,
    track_user_action
)

from .formatters import (
    StructuredJSONFormatter,
    StructuredConsoleFormatter,
    SecurityLogFormatter,
    PerformanceLogFormatter,
    ErrorCorrelationFormatter,
    get_formatter
)

from .filters import (
    CorrelationFilter,
    SecurityFilter,
    PerformanceFilter,
    ErrorSeverityFilter,
    SensitiveDataFilter,
    RateLimitFilter,
    BusinessEventFilter,
    get_filter
)

# Version information
__version__ = '1.0.0'
__author__ = 'PRS Development Team'

# Default logger for the module
logger = StructuredLogger(__name__)

# Convenience imports for common use cases
__all__ = [
    # Core logging
    'StructuredLogger',
    'EventType',
    'LogLevel',
    'structured_logger',
    'logger',
    
    # Context management
    'set_user_context',
    'set_request_context',
    'get_correlation_id',
    'with_correlation_id',
    
    # Error correlation
    'error_tracker',
    'track_error',
    'get_error_summary',
    'get_error_cluster',
    
    # Middleware
    'EnhancedExceptionMiddleware',
    'PerformanceMonitoringMiddleware',
    'SecurityEventMiddleware',
    'CorrelationMiddleware',
    
    # Dashboard
    'get_error_monitoring_urls',
    
    # Integration
    'integrate_with_settings',
    'setup_development_logging',
    'setup_production_logging',
    
    # Convenience functions
    'log_business_event',
    'log_security_event',
    'log_performance_issue',
    'track_user_action',
    
    # Formatters and filters
    'get_formatter',
    'get_filter',
]

# Module initialization
def initialize_logging_system():
    """Initialize the enhanced logging system"""
    try:
        integrator = LoggingSystemIntegrator()
        integrator.initialize_system()
        
        logger.info(
            EventType.SYSTEM_ERROR,
            "Enhanced logging system initialized",
            extra_data={
                'version': __version__,
                'components': [
                    'structured_logging',
                    'error_correlation', 
                    'performance_monitoring',
                    'security_monitoring',
                    'error_dashboard'
                ]
            },
            tags=['initialization', 'logging']
        )
        
        return True
        
    except Exception as e:
        logger.error(
            EventType.SYSTEM_ERROR,
            "Failed to initialize logging system",
            exception=e,
            tags=['initialization', 'error']
        )
        return False

# Auto-initialize in development
import os
if os.environ.get('DJANGO_SETTINGS_MODULE') and 'development' in os.environ.get('DJANGO_SETTINGS_MODULE', ''):
    try:
        initialize_logging_system()
    except Exception:
        pass  # Fail silently during imports
