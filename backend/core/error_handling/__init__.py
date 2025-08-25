"""
Enhanced Error Handling System for PRS Backend

This module provides comprehensive error handling capabilities including:
- Structured logging with correlation tracking
- Error correlation and pattern analysis
- Circuit breakers and retry mechanisms
- Graceful degradation and recovery strategies
- User-friendly error messages
- Automated error escalation
- Error monitoring dashboard

Components:
1. Structured Logging (core/logging/)
   - StructuredLogger: Enhanced logging with correlation IDs
   - ErrorCorrelationTracker: Track and analyze error patterns
   - ErrorMonitoringDashboard: Web-based error monitoring

2. Enhanced Error Handlers
   - EnhancedErrorHandler: Main error handling with recovery
   - RecoveryStrategies: Automatic error recovery mechanisms
   - EscalationRules: Automated error escalation

3. Error Workflows
   - CircuitBreaker: Fault tolerance patterns
   - RetryMechanism: Advanced retry strategies
   - GracefulDegradation: Fallback mechanisms

4. User-Friendly Messages
   - MessageGenerator: Context-aware error messages
   - UserActions: Actionable error responses
   - HelpResources: Contextual help and guidance

Usage Examples:

    # Basic enhanced error handling
    from core.error_handling import enhanced_error_handler, error_handling_context
    
    try:
        # Risky operation
        result = perform_operation()
    except Exception as e:
        error_response = enhanced_error_handler.handle_error(e, user_id=123)
        return JsonResponse(error_response)
    
    # Context manager for automatic handling
    with error_handling_context('user_operation', user_id=123) as ctx:
        result = perform_user_operation()
    
    # Protected function decorator
    from core.error_handling import protected, CircuitBreakerConfig, RetryConfig
    
    @protected('database_operation',
               circuit_breaker_config=CircuitBreakerConfig(failure_threshold=3),
               retry_config=RetryConfig(max_attempts=3))
    def database_operation():
        return query_database()
    
    # User-friendly error messages
    from core.error_handling import generate_user_friendly_error
    
    try:
        perform_operation()
    except Exception as e:
        friendly_error = generate_user_friendly_error(e, user_id=123)
        return {
            'error': {
                'title': friendly_error.title,
                'message': friendly_error.message,
                'actions': [action.__dict__ for action in friendly_error.actions]
            }
        }
"""

# Core error handling components
from .enhanced_error_handlers import (
    EnhancedErrorHandler,
    RecoveryStrategy,
    ErrorSeverity,
    RecoveryResult,
    UserFriendlyError,
    enhanced_error_handler,
    error_handling_context,
    EnhancedAPIException,
    handle_database_error,
    handle_validation_error,
    handle_permission_error
)

# Error workflow components
from .error_workflows import (
    CircuitBreaker,
    RetryMechanism,
    GracefulDegradation,
    ErrorWorkflowManager,
    CircuitState,
    RetryPolicy,
    CircuitBreakerConfig,
    RetryConfig,
    DegradationConfig,
    workflow_manager,
    protected,
    CircuitBreakerOpenException,
    RetryExhaustedException,
    create_database_protection,
    create_api_protection,
    create_external_service_protection
)

# User-friendly messaging components
from .user_friendly_messages import (
    MessageGenerator,
    MessageContextAnalyzer,
    UserFriendlyMessage,
    UserAction,
    HelpResource,
    MessageTone,
    ActionType,
    message_generator,
    generate_user_friendly_error,
    get_error_actions,
    get_help_resources
)

# Import logging components
from ..logging import (
    StructuredLogger,
    EventType,
    error_tracker,
    track_error,
    get_error_summary,
    structured_logger,
    get_correlation_id,
    set_user_context,
    log_business_event,
    log_security_event
)

# Version information
__version__ = '1.0.0'
__author__ = 'PRS Development Team'

# Main logger for the error handling system
logger = StructuredLogger('error_handling')

# Convenience imports and functions
__all__ = [
    # Enhanced error handlers
    'enhanced_error_handler',
    'error_handling_context',
    'EnhancedErrorHandler',
    'RecoveryStrategy',
    'ErrorSeverity',
    'EnhancedAPIException',
    'handle_database_error',
    'handle_validation_error',
    'handle_permission_error',
    
    # Error workflows
    'workflow_manager',
    'protected',
    'CircuitBreaker',
    'RetryMechanism', 
    'GracefulDegradation',
    'CircuitBreakerConfig',
    'RetryConfig',
    'DegradationConfig',
    'CircuitState',
    'RetryPolicy',
    'create_database_protection',
    'create_api_protection',
    'create_external_service_protection',
    
    # User-friendly messages
    'message_generator',
    'generate_user_friendly_error',
    'get_error_actions',
    'get_help_resources',
    'MessageTone',
    'ActionType',
    'UserAction',
    'HelpResource',
    
    # Logging integration
    'track_error',
    'get_error_summary',
    'log_business_event',
    'log_security_event',
    'structured_logger',
    'EventType',
    
    # Exceptions
    'CircuitBreakerOpenException',
    'RetryExhaustedException',
]


def initialize_error_handling_system():
    """Initialize the complete error handling system"""
    
    logger.info(
        EventType.SYSTEM_ERROR,
        "Initializing enhanced error handling system",
        extra_data={
            'version': __version__,
            'components': [
                'enhanced_error_handlers',
                'error_workflows', 
                'user_friendly_messages',
                'structured_logging',
                'error_correlation',
                'error_monitoring'
            ]
        },
        tags=['initialization', 'error_handling']
    )
    
    try:
        # Initialize workflow manager with standard protections
        create_database_protection()
        create_api_protection() 
        create_external_service_protection()
        
        # Log successful initialization
        logger.info(
            EventType.SYSTEM_ERROR,
            "Enhanced error handling system initialized successfully",
            extra_data={
                'circuit_breakers': len(workflow_manager.circuit_breakers),
                'retry_mechanisms': len(workflow_manager.retry_mechanisms),
                'degradation_handlers': len(workflow_manager.degradation_handlers)
            },
            tags=['initialization', 'success']
        )
        
        return True
        
    except Exception as e:
        logger.error(
            EventType.SYSTEM_ERROR,
            "Failed to initialize error handling system",
            exception=e,
            tags=['initialization', 'failed']
        )
        return False


def get_system_status():
    """Get comprehensive error handling system status"""
    
    return {
        'version': __version__,
        'components': {
            'enhanced_error_handler': {
                'status': 'active',
                'class': enhanced_error_handler.__class__.__name__
            },
            'workflow_manager': workflow_manager.get_status(),
            'message_generator': {
                'status': 'active',
                'class': message_generator.__class__.__name__
            },
            'error_tracker': {
                'status': 'active',
                'cluster_count': len(error_tracker.error_clusters),
                'recent_errors': len(error_tracker.recent_errors)
            }
        },
        'metrics': {
            'total_error_clusters': len(error_tracker.error_clusters),
            'circuit_breakers': len(workflow_manager.circuit_breakers),
            'retry_mechanisms': len(workflow_manager.retry_mechanisms),
            'degradation_handlers': len(workflow_manager.degradation_handlers)
        }
    }


# Module-level convenience functions
def handle_error_with_recovery(error: Exception, operation_name: str = None,
                              user_id: int = None, **context):
    """
    Handle error with full recovery and user-friendly messaging
    
    This is the main entry point for comprehensive error handling.
    """
    
    # Add operation context
    if operation_name:
        context['operation_name'] = operation_name
    
    # Handle error with enhanced handler
    error_response = enhanced_error_handler.handle_error(
        error=error,
        context=context,
        user_id=user_id
    )
    
    # Generate user-friendly message
    friendly_message = generate_user_friendly_error(error, user_id=user_id)
    
    # Combine responses
    return {
        'error': error_response['error'],
        'recovery': error_response['recovery'],
        'user_message': {
            'title': friendly_message.title,
            'message': friendly_message.message,
            'severity': friendly_message.severity,
            'actions': [action.__dict__ for action in friendly_message.actions],
            'help_resources': [resource.__dict__ for resource in friendly_message.help_resources]
        },
        'meta': error_response['meta']
    }


def create_error_response(error: Exception, user_id: int = None, **context):
    """
    Create a complete error response ready for API return
    """
    
    response_data = handle_error_with_recovery(error, user_id=user_id, **context)
    
    # Determine HTTP status code
    status_map = {
        'ValidationError': 400,
        'PermissionDenied': 403,
        'AuthenticationFailed': 401,
        'NotFound': 404,
        'TimeoutError': 408,
        'DatabaseError': 503,
        'ConnectionError': 503
    }
    
    status_code = status_map.get(type(error).__name__, 500)
    
    return {
        'status_code': status_code,
        'data': response_data,
        'headers': {
            'X-Error-Correlation-ID': response_data['meta'].get('request_id'),
            'X-Error-Recovery-Available': str(response_data['recovery'].get('attempted', False)).lower()
        }
    }


# Auto-initialize in development
import os
if os.environ.get('DJANGO_SETTINGS_MODULE'):
    try:
        initialize_error_handling_system()
    except Exception:
        pass  # Fail silently during imports
