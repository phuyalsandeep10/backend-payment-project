"""
Exception Handler Classes for PRS Backend
Focused, reusable exception handling components
"""

import traceback
from typing import Any, Dict, Optional
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import DatabaseError, IntegrityError, OperationalError
from rest_framework.exceptions import (
    ValidationError as DRFValidationError, 
    AuthenticationFailed, 
    PermissionDenied, 
    Throttled
)
from rest_framework import status

from ...core_config.error_handling.standard_responses import StandardErrorResponse
from .structured_logger import StructuredLogger, EventType


class ExceptionClassifier:
    """Classifies exceptions and determines appropriate responses"""
    
    @staticmethod
    def get_event_type(exception: Exception) -> EventType:
        """Determine appropriate event type for exception"""
        if isinstance(exception, (DatabaseError, OperationalError, IntegrityError)):
            return EventType.DATABASE_ERROR
        elif isinstance(exception, (ValidationError, DRFValidationError)):
            return EventType.VALIDATION_ERROR
        elif isinstance(exception, AuthenticationFailed):
            return EventType.AUTH_FAILED
        elif isinstance(exception, PermissionDenied):
            return EventType.ACCESS_DENIED
        elif isinstance(exception, Throttled):
            return EventType.RATE_LIMIT_EXCEEDED
        elif isinstance(exception, (MemoryError, IOError, OSError)):
            return EventType.SYSTEM_ERROR
        else:
            return EventType.UNHANDLED_EXCEPTION


class ResponseBuilder:
    """Builds standardized error responses"""
    
    @staticmethod
    def create_error_response(exception: Exception, correlation_id: str) -> StandardErrorResponse:
        """Create standardized error response based on exception type"""
        
        # Database errors
        if isinstance(exception, (DatabaseError, OperationalError)):
            if 'connection' in str(exception).lower():
                return StandardErrorResponse(
                    error_code='DATABASE_CONNECTION_ERROR',
                    message='Database connection error. Please try again.',
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    request_id=correlation_id
                )
            else:
                return StandardErrorResponse(
                    error_code='DATABASE_ERROR',
                    message='Database error occurred. Please contact support if this persists.',
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    request_id=correlation_id
                )
        
        # Integrity constraint violations
        elif isinstance(exception, IntegrityError):
            return StandardErrorResponse(
                error_code='DATA_INTEGRITY_ERROR',
                message='Data integrity constraint violation. The operation conflicts with existing data.',
                status_code=status.HTTP_409_CONFLICT,
                request_id=correlation_id
            )
        
        # Validation errors
        elif isinstance(exception, (ValidationError, DRFValidationError)):
            details = ResponseBuilder._extract_validation_details(exception)
            return StandardErrorResponse(
                error_code='VALIDATION_ERROR',
                message='Validation failed. Please check your input.',
                details=details,
                status_code=status.HTTP_400_BAD_REQUEST,
                request_id=correlation_id
            )
        
        # Authentication errors
        elif isinstance(exception, AuthenticationFailed):
            return StandardErrorResponse(
                error_code='AUTHENTICATION_FAILED',
                message='Authentication failed. Please check your credentials.',
                status_code=status.HTTP_401_UNAUTHORIZED,
                request_id=correlation_id
            )
        
        # Permission errors
        elif isinstance(exception, PermissionDenied):
            return StandardErrorResponse(
                error_code='PERMISSION_DENIED',
                message='You do not have permission to perform this action.',
                status_code=status.HTTP_403_FORBIDDEN,
                request_id=correlation_id
            )
        
        # Rate limiting
        elif isinstance(exception, Throttled):
            retry_after = getattr(exception, 'wait', None)
            return StandardErrorResponse(
                error_code='RATE_LIMIT_EXCEEDED',
                message=f'Rate limit exceeded. Please try again in {int(retry_after)} seconds.' if retry_after else 'Rate limit exceeded.',
                details={'retry_after': retry_after} if retry_after else None,
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                request_id=correlation_id
            )
        
        # Critical system errors
        elif isinstance(exception, MemoryError):
            return StandardErrorResponse(
                error_code='MEMORY_ERROR',
                message='System is experiencing high load. Please try again later.',
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                request_id=correlation_id
            )
        
        elif isinstance(exception, TimeoutError):
            return StandardErrorResponse(
                error_code='TIMEOUT_ERROR',
                message='Request timed out. Please try again.',
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                request_id=correlation_id
            )
        
        # File/IO errors
        elif isinstance(exception, (IOError, OSError)):
            if 'disk' in str(exception).lower() or 'space' in str(exception).lower():
                return StandardErrorResponse(
                    error_code='DISK_SPACE_ERROR',
                    message='System storage is full. Please contact support.',
                    status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                    request_id=correlation_id
                )
            else:
                return StandardErrorResponse(
                    error_code='FILE_SYSTEM_ERROR',
                    message='File system error occurred. Please try again.',
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    request_id=correlation_id
                )
        
        # Import/Module errors (configuration issues)
        elif isinstance(exception, ImportError):
            return StandardErrorResponse(
                error_code='SERVICE_CONFIGURATION_ERROR',
                message='Service configuration error. Please contact support.',
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                request_id=correlation_id
            )
        
        # Generic exceptions
        else:
            # Check if it's a known business logic exception
            if hasattr(exception, 'error_code'):
                return StandardErrorResponse(
                    error_code=exception.error_code,
                    message=str(exception),
                    status_code=getattr(exception, 'status_code', status.HTTP_400_BAD_REQUEST),
                    request_id=correlation_id
                )
            
            # Generic server error
            return StandardErrorResponse(
                error_code='INTERNAL_SERVER_ERROR',
                message='An unexpected error occurred. Please try again later.' if not settings.DEBUG else str(exception),
                details={'exception_type': type(exception).__name__} if settings.DEBUG else None,
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                request_id=correlation_id
            )
    
    @staticmethod
    def _extract_validation_details(exception) -> Dict[str, Any]:
        """Extract validation details from exception"""
        details = {}
        if hasattr(exception, 'detail'):
            if isinstance(exception.detail, dict):
                details = exception.detail
            elif isinstance(exception.detail, list):
                details = {'errors': exception.detail}
            else:
                details = {'message': str(exception.detail)}
        elif hasattr(exception, 'message_dict'):
            details = exception.message_dict
        return details


class ExceptionLogger:
    """Handles structured logging of exceptions"""
    
    def __init__(self):
        self.logger = StructuredLogger('exception_handler')
    
    def log_exception(self, exception: Exception, request, error_response: StandardErrorResponse,
                     error_cluster, correlation_id: str):
        """Log exception with structured logging"""
        
        # Determine event type and severity
        event_type = ExceptionClassifier.get_event_type(exception)
        
        # Prepare context data
        context_data = {
            'exception_type': type(exception).__name__,
            'exception_message': str(exception),
            'error_code': error_response.error_code,
            'status_code': error_response.status_code,
            'stack_trace': traceback.format_exc(),
            'view_name': self._get_view_name(request),
        }
        
        # Add error cluster information if available
        if error_cluster:
            context_data['error_cluster'] = {
                'signature_hash': error_cluster.signature.signature_hash,
                'occurrence_count': error_cluster.occurrence_count,
                'severity_level': error_cluster.severity_level,
                'first_occurrence': error_cluster.first_occurrence,
            }
        
        # Add request-specific context
        context_data['request_data'] = {
            'method': request.method,
            'path': request.path,
            'query_string': request.META.get('QUERY_STRING', ''),
            'content_type': request.META.get('CONTENT_TYPE', ''),
            'content_length': request.META.get('CONTENT_LENGTH', 0),
        }
        
        # Log with appropriate severity
        if error_response.status_code >= 500:
            self.logger.error(
                event_type,
                f"Server error: {type(exception).__name__} in {self._get_view_name(request)}",
                exception=exception,
                extra_data=context_data,
                tags=['server_error', 'exception', type(exception).__name__.lower()],
                correlation_id=correlation_id
            )
        elif error_response.status_code >= 400:
            self.logger.warning(
                event_type,
                f"Client error: {type(exception).__name__} in {self._get_view_name(request)}",
                extra_data=context_data,
                tags=['client_error', 'exception', type(exception).__name__.lower()],
                correlation_id=correlation_id
            )
        else:
            self.logger.info(
                event_type,
                f"Exception handled: {type(exception).__name__} in {self._get_view_name(request)}",
                extra_data=context_data,
                tags=['handled_exception', type(exception).__name__.lower()],
                correlation_id=correlation_id
            )
    
    def _get_view_name(self, request) -> str:
        """Get view name from request"""
        try:
            resolver_match = request.resolver_match
            if resolver_match:
                if hasattr(resolver_match, 'func'):
                    if hasattr(resolver_match.func, '__name__'):
                        return resolver_match.func.__name__
                    elif hasattr(resolver_match.func, 'cls'):
                        return f"{resolver_match.func.cls.__name__}.{resolver_match.func.actions.get(request.method.lower(), 'unknown')}"
                return f"view_{resolver_match.view_name}"
            return "unknown_view"
        except:
            return "unknown_view"


class CriticalPatternDetector:
    """Detects critical error patterns requiring immediate attention"""
    
    def __init__(self):
        self.logger = StructuredLogger('critical_pattern_detector')
    
    def check_critical_patterns(self, exception: Exception, error_cluster):
        """Check for critical error patterns that need immediate attention"""
        
        # Critical exception types
        critical_exceptions = [MemoryError, SystemExit]
        
        if type(exception) in critical_exceptions:
            self.logger.critical(
                EventType.SYSTEM_ERROR,
                f"Critical exception detected: {type(exception).__name__}",
                exception=exception,
                extra_data={
                    'requires_immediate_attention': True,
                    'system_impact': 'high',
                    'recommended_action': 'investigate_system_resources'
                },
                tags=['critical', 'immediate_attention', type(exception).__name__.lower()]
            )
        
        # Check for error spikes
        if error_cluster and error_cluster.occurrence_count >= 10:
            recent_count = len([occ for occ in error_cluster.occurrences[-10:]])
            if recent_count >= 5:  # 5 occurrences in recent history
                self.logger.critical(
                    EventType.SYSTEM_ERROR,
                    f"Error spike detected: {type(exception).__name__} ({recent_count} recent occurrences)",
                    extra_data={
                        'signature_hash': error_cluster.signature.signature_hash,
                        'recent_occurrences': recent_count,
                        'total_occurrences': error_cluster.occurrence_count,
                        'requires_investigation': True
                    },
                    tags=['error_spike', 'critical', 'pattern_analysis']
                )
        
        # Check for database connection issues
        if isinstance(exception, (DatabaseError, OperationalError)):
            if 'connection' in str(exception).lower():
                self.logger.critical(
                    EventType.DATABASE_ERROR,
                    "Database connection issue detected",
                    exception=exception,
                    extra_data={
                        'system_component': 'database',
                        'impact_level': 'service_affecting',
                        'recommended_action': 'check_database_connectivity'
                    },
                    tags=['database', 'connectivity', 'service_affecting']
                )
