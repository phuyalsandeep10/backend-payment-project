"""
Enhanced structured logging system for PRS Backend
Provides comprehensive error tracking, correlation, and monitoring integration
"""

import json
import logging
import uuid
import traceback
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
from contextvars import ContextVar
from dataclasses import dataclass, asdict
from enum import Enum

from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import AbstractUser

# Context variables for request tracking
correlation_id_var: ContextVar[str] = ContextVar('correlation_id', default=None)
user_context_var: ContextVar[Dict[str, Any]] = ContextVar('user_context', default={})
request_context_var: ContextVar[Dict[str, Any]] = ContextVar('request_context', default={})


class LogLevel(Enum):
    """Standard log levels with severity scoring"""
    DEBUG = ("DEBUG", 0)
    INFO = ("INFO", 1)
    WARNING = ("WARNING", 2)
    ERROR = ("ERROR", 3)
    CRITICAL = ("CRITICAL", 4)
    
    def __init__(self, level_name: str, severity: int):
        self.level_name = level_name
        self.severity = severity


class EventType(Enum):
    """Categorized event types for better log organization"""
    # Application Events
    REQUEST_RECEIVED = "request_received"
    REQUEST_COMPLETED = "request_completed"
    REQUEST_FAILED = "request_failed"
    
    # Authentication Events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    AUTH_FAILED = "auth_failed"
    TOKEN_EXPIRED = "token_expired"
    
    # Business Logic Events
    DEAL_CREATED = "deal_created"
    DEAL_UPDATED = "deal_updated"
    DEAL_DELETED = "deal_deleted"
    PAYMENT_PROCESSED = "payment_processed"
    COMMISSION_CALCULATED = "commission_calculated"
    
    # System Events
    DATABASE_ERROR = "database_error"
    CACHE_ERROR = "cache_error"
    EXTERNAL_API_ERROR = "external_api_error"
    PERFORMANCE_ISSUE = "performance_issue"
    
    # Security Events
    SECURITY_VIOLATION = "security_violation"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    ACCESS_DENIED = "access_denied"
    
    # Error Events
    VALIDATION_ERROR = "validation_error"
    BUSINESS_LOGIC_ERROR = "business_logic_error"
    SYSTEM_ERROR = "system_error"
    UNHANDLED_EXCEPTION = "unhandled_exception"


@dataclass
class LogContext:
    """Structured log context information"""
    # Request information
    correlation_id: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    
    # User context
    user_id: Optional[int] = None
    user_email: Optional[str] = None
    organization_id: Optional[int] = None
    organization_name: Optional[str] = None
    
    # Request context
    method: Optional[str] = None
    path: Optional[str] = None
    endpoint: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    # Application context
    service_name: Optional[str] = None
    module_name: Optional[str] = None
    function_name: Optional[str] = None
    
    # Performance context
    duration_ms: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    
    # Business context
    entity_type: Optional[str] = None
    entity_id: Optional[Union[int, str]] = None
    action: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values"""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class LogEvent:
    """Structured log event"""
    timestamp: str
    level: str
    event_type: str
    message: str
    context: LogContext
    
    # Optional fields
    exception_type: Optional[str] = None
    exception_message: Optional[str] = None
    stack_trace: Optional[str] = None
    extra_data: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = {
            'timestamp': self.timestamp,
            'level': self.level,
            'event_type': self.event_type,
            'message': self.message,
            'context': self.context.to_dict(),
        }
        
        # Add optional fields if present
        if self.exception_type:
            data['exception'] = {
                'type': self.exception_type,
                'message': self.exception_message,
                'stack_trace': self.stack_trace
            }
        
        if self.extra_data:
            data['extra'] = self.extra_data
            
        if self.tags:
            data['tags'] = self.tags
            
        return data


class StructuredLogger:
    """Enhanced structured logger with correlation tracking"""
    
    def __init__(self, name: str = None):
        self.name = name or __name__
        self.logger = logging.getLogger(self.name)
        self._thread_local = threading.local()
    
    def _get_correlation_id(self) -> str:
        """Get or generate correlation ID"""
        correlation_id = correlation_id_var.get()
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
            correlation_id_var.set(correlation_id)
        return correlation_id
    
    def _get_current_context(self) -> LogContext:
        """Get current logging context"""
        # Get context from context vars
        user_context = user_context_var.get({})
        request_context = request_context_var.get({})
        
        return LogContext(
            correlation_id=self._get_correlation_id(),
            request_id=request_context.get('request_id'),
            trace_id=request_context.get('trace_id'),
            
            # User context
            user_id=user_context.get('user_id'),
            user_email=user_context.get('user_email'),
            organization_id=user_context.get('organization_id'),
            organization_name=user_context.get('organization_name'),
            
            # Request context
            method=request_context.get('method'),
            path=request_context.get('path'),
            endpoint=request_context.get('endpoint'),
            user_agent=request_context.get('user_agent'),
            ip_address=request_context.get('ip_address'),
            
            # Application context
            service_name=getattr(settings, 'SERVICE_NAME', 'prs-backend'),
            module_name=self.name.split('.')[0] if '.' in self.name else self.name,
        )
    
    def _log_event(self, level: LogLevel, event_type: EventType, message: str,
                   exception: Exception = None, extra_data: Dict[str, Any] = None,
                   tags: List[str] = None, **kwargs):
        """Log a structured event"""
        
        # Get current context and update with kwargs
        context = self._get_current_context()
        
        # Update context with any provided kwargs
        for key, value in kwargs.items():
            if hasattr(context, key):
                setattr(context, key, value)
        
        # Create log event
        log_event = LogEvent(
            timestamp=timezone.now().isoformat(),
            level=level.level_name,
            event_type=event_type.value,
            message=message,
            context=context,
            extra_data=extra_data,
            tags=tags or []
        )
        
        # Add exception information if provided
        if exception:
            log_event.exception_type = type(exception).__name__
            log_event.exception_message = str(exception)
            log_event.stack_trace = traceback.format_exc()
            
            # Add exception tag
            if log_event.tags is None:
                log_event.tags = []
            log_event.tags.append('exception')
        
        # Convert to dict and log as JSON
        log_data = log_event.to_dict()
        
        # Use standard logging with extra data
        self.logger.log(
            getattr(logging, level.level_name),
            json.dumps(log_data, default=str),
            extra={
                'correlation_id': context.correlation_id,
                'user_id': context.user_id,
                'event_type': event_type.value,
                'structured': True
            }
        )
    
    # Convenience methods for different log levels
    def debug(self, event_type: EventType, message: str, **kwargs):
        """Log debug event"""
        self._log_event(LogLevel.DEBUG, event_type, message, **kwargs)
    
    def info(self, event_type: EventType, message: str, **kwargs):
        """Log info event"""
        self._log_event(LogLevel.INFO, event_type, message, **kwargs)
    
    def warning(self, event_type: EventType, message: str, **kwargs):
        """Log warning event"""
        self._log_event(LogLevel.WARNING, event_type, message, **kwargs)
    
    def error(self, event_type: EventType, message: str, exception: Exception = None, **kwargs):
        """Log error event"""
        self._log_event(LogLevel.ERROR, event_type, message, exception=exception, **kwargs)
    
    def critical(self, event_type: EventType, message: str, exception: Exception = None, **kwargs):
        """Log critical event"""
        self._log_event(LogLevel.CRITICAL, event_type, message, exception=exception, **kwargs)
    
    # Business event logging methods
    def log_request_received(self, method: str, path: str, **kwargs):
        """Log incoming request"""
        self.info(
            EventType.REQUEST_RECEIVED,
            f"{method} {path} - Request received",
            method=method,
            path=path,
            **kwargs
        )
    
    def log_request_completed(self, method: str, path: str, status_code: int,
                             duration_ms: float, **kwargs):
        """Log completed request"""
        self.info(
            EventType.REQUEST_COMPLETED,
            f"{method} {path} - Request completed ({status_code}) in {duration_ms:.1f}ms",
            method=method,
            path=path,
            duration_ms=duration_ms,
            extra_data={'status_code': status_code},
            **kwargs
        )
    
    def log_request_failed(self, method: str, path: str, error: Exception,
                          status_code: int = None, **kwargs):
        """Log failed request"""
        self.error(
            EventType.REQUEST_FAILED,
            f"{method} {path} - Request failed",
            exception=error,
            method=method,
            path=path,
            extra_data={'status_code': status_code} if status_code else None,
            **kwargs
        )
    
    def log_user_action(self, action: str, user_id: int = None,
                       entity_type: str = None, entity_id: Union[int, str] = None,
                       **kwargs):
        """Log user action"""
        self.info(
            EventType.USER_LOGIN if 'login' in action.lower() else EventType.REQUEST_COMPLETED,
            f"User action: {action}",
            action=action,
            user_id=user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            **kwargs
        )
    
    def log_database_error(self, operation: str, table: str = None,
                          error: Exception = None, **kwargs):
        """Log database error"""
        message = f"Database error during {operation}"
        if table:
            message += f" on {table}"
            
        self.error(
            EventType.DATABASE_ERROR,
            message,
            exception=error,
            extra_data={'operation': operation, 'table': table},
            tags=['database', 'error'],
            **kwargs
        )
    
    def log_security_event(self, event_description: str, severity: str = 'medium',
                          ip_address: str = None, **kwargs):
        """Log security event"""
        event_type = EventType.SECURITY_VIOLATION
        
        if 'rate limit' in event_description.lower():
            event_type = EventType.RATE_LIMIT_EXCEEDED
        elif 'access denied' in event_description.lower():
            event_type = EventType.ACCESS_DENIED
        elif 'suspicious' in event_description.lower():
            event_type = EventType.SUSPICIOUS_ACTIVITY
        
        level = LogLevel.CRITICAL if severity == 'high' else LogLevel.WARNING
        
        self._log_event(
            level,
            event_type,
            f"Security event: {event_description}",
            ip_address=ip_address,
            extra_data={'severity': severity},
            tags=['security', severity],
            **kwargs
        )
    
    def log_performance_issue(self, operation: str, duration_ms: float,
                             threshold_ms: float = 1000, **kwargs):
        """Log performance issue"""
        self.warning(
            EventType.PERFORMANCE_ISSUE,
            f"Performance issue: {operation} took {duration_ms:.1f}ms (threshold: {threshold_ms}ms)",
            duration_ms=duration_ms,
            extra_data={'operation': operation, 'threshold_ms': threshold_ms},
            tags=['performance', 'slow'],
            **kwargs
        )
    
    def log_business_event(self, event_name: str, entity_type: str = None,
                          entity_id: Union[int, str] = None, **kwargs):
        """Log business event"""
        # Map common business events to specific types
        event_type_map = {
            'deal_created': EventType.DEAL_CREATED,
            'deal_updated': EventType.DEAL_UPDATED,
            'deal_deleted': EventType.DEAL_DELETED,
            'payment_processed': EventType.PAYMENT_PROCESSED,
            'commission_calculated': EventType.COMMISSION_CALCULATED,
        }
        
        event_type = event_type_map.get(event_name.lower(), EventType.REQUEST_COMPLETED)
        
        self.info(
            event_type,
            f"Business event: {event_name}",
            action=event_name,
            entity_type=entity_type,
            entity_id=entity_id,
            tags=['business_event'],
            **kwargs
        )


class CorrelationMiddleware:
    """Middleware to set up correlation IDs and request context"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = StructuredLogger('middleware.correlation')
    
    def __call__(self, request):
        # Generate or extract correlation ID
        correlation_id = (
            request.META.get('HTTP_X_CORRELATION_ID') or
            request.META.get('HTTP_X_REQUEST_ID') or
            str(uuid.uuid4())
        )
        
        # Set context variables
        correlation_id_var.set(correlation_id)
        
        # Set user context
        if hasattr(request, 'user') and request.user.is_authenticated:
            user_context = {
                'user_id': request.user.id,
                'user_email': request.user.email,
            }
            
            # Add organization info if available
            if hasattr(request.user, 'organization'):
                user_context.update({
                    'organization_id': request.user.organization.id,
                    'organization_name': request.user.organization.name,
                })
            
            user_context_var.set(user_context)
        
        # Set request context
        request_context = {
            'request_id': correlation_id,
            'method': request.method,
            'path': request.path,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'ip_address': self._get_client_ip(request),
        }
        request_context_var.set(request_context)
        
        # Add correlation ID to request for other middleware
        request.correlation_id = correlation_id
        
        # Log request received
        start_time = time.time()
        self.logger.log_request_received(
            method=request.method,
            path=request.path,
            ip_address=request_context['ip_address']
        )
        
        try:
            response = self.get_response(request)
            
            # Log successful response
            duration_ms = (time.time() - start_time) * 1000
            self.logger.log_request_completed(
                method=request.method,
                path=request.path,
                status_code=response.status_code,
                duration_ms=duration_ms
            )
            
            # Add correlation ID to response headers
            response['X-Correlation-ID'] = correlation_id
            
            return response
            
        except Exception as e:
            # Log failed request
            duration_ms = (time.time() - start_time) * 1000
            self.logger.log_request_failed(
                method=request.method,
                path=request.path,
                error=e
            )
            raise
    
    def _get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


# Global logger instance
structured_logger = StructuredLogger('prs.application')

# Context management functions
def set_user_context(user: AbstractUser, organization=None):
    """Set user context for current request"""
    context = {
        'user_id': user.id,
        'user_email': user.email,
    }
    
    if organization:
        context.update({
            'organization_id': organization.id,
            'organization_name': organization.name,
        })
    elif hasattr(user, 'organization'):
        context.update({
            'organization_id': user.organization.id,
            'organization_name': user.organization.name,
        })
    
    user_context_var.set(context)


def set_request_context(**kwargs):
    """Set additional request context"""
    current_context = request_context_var.get({})
    current_context.update(kwargs)
    request_context_var.set(current_context)


def get_correlation_id() -> Optional[str]:
    """Get current correlation ID"""
    return correlation_id_var.get()


def with_correlation_id(correlation_id: str):
    """Context manager to set correlation ID"""
    class CorrelationContext:
        def __enter__(self):
            correlation_id_var.set(correlation_id)
            return self
            
        def __exit__(self, exc_type, exc_val, exc_tb):
            correlation_id_var.set(None)
    
    return CorrelationContext()
