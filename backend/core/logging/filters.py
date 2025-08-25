"""
Custom logging filters for structured logging
"""

import logging
import re
from typing import Set, List, Optional, Pattern
from .structured_logger import correlation_id_var, user_context_var, request_context_var


class CorrelationFilter(logging.Filter):
    """
    Filter to add correlation ID and context to log records
    """
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add correlation and context information to log record"""
        
        # Add correlation ID if not already present
        if not hasattr(record, 'correlation_id'):
            correlation_id = correlation_id_var.get()
            if correlation_id:
                record.correlation_id = correlation_id
        
        # Add user context
        user_context = user_context_var.get({})
        if user_context:
            record.user_id = user_context.get('user_id')
            record.user_email = user_context.get('user_email')
            record.organization_id = user_context.get('organization_id')
        
        # Add request context
        request_context = request_context_var.get({})
        if request_context:
            record.request_path = request_context.get('path')
            record.request_method = request_context.get('method')
            record.ip_address = request_context.get('ip_address')
            record.user_agent = request_context.get('user_agent')
        
        return True


class SecurityFilter(logging.Filter):
    """
    Filter for security-related log records
    """
    
    # Security-related logger names
    SECURITY_LOGGERS = {
        'security_monitoring',
        'django.security',
        'authentication',
        'authorization',
        'security_events'
    }
    
    # Security-related event types
    SECURITY_EVENT_TYPES = {
        'auth_failed',
        'access_denied',
        'rate_limit_exceeded',
        'security_violation',
        'suspicious_activity',
        'user_login',
        'user_logout',
        'token_expired'
    }
    
    # Security-related keywords in messages
    SECURITY_KEYWORDS = {
        'authentication', 'authorization', 'permission', 'access denied',
        'unauthorized', 'forbidden', 'security', 'attack', 'injection',
        'xss', 'csrf', 'rate limit', 'brute force', 'suspicious'
    }
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter security-related log records"""
        
        # Check if logger is security-related
        if any(sec_logger in record.name for sec_logger in self.SECURITY_LOGGERS):
            record.security_event = True
            return True
        
        # Check if event type is security-related
        if hasattr(record, 'event_type') and record.event_type in self.SECURITY_EVENT_TYPES:
            record.security_event = True
            return True
        
        # Check message content for security keywords
        message = record.getMessage().lower()
        if any(keyword in message for keyword in self.SECURITY_KEYWORDS):
            record.security_event = True
            return True
        
        # Check for security-related exception types
        if record.exc_info and record.exc_info[0]:
            exception_name = record.exc_info[0].__name__.lower()
            if any(keyword in exception_name for keyword in ['auth', 'permission', 'security']):
                record.security_event = True
                return True
        
        # Not a security event
        return False


class PerformanceFilter(logging.Filter):
    """
    Filter for performance-related log records
    """
    
    # Performance-related logger names
    PERFORMANCE_LOGGERS = {
        'performance_monitoring',
        'django.db.backends',
        'cache',
        'celery'
    }
    
    # Performance-related event types
    PERFORMANCE_EVENT_TYPES = {
        'performance_issue',
        'request_completed',
        'database_query',
        'cache_miss',
        'slow_operation'
    }
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter performance-related log records"""
        
        # Check if logger is performance-related
        if any(perf_logger in record.name for perf_logger in self.PERFORMANCE_LOGGERS):
            record.performance_event = True
            return True
        
        # Check if event type is performance-related
        if hasattr(record, 'event_type') and record.event_type in self.PERFORMANCE_EVENT_TYPES:
            record.performance_event = True
            return True
        
        # Check if record has performance metrics
        performance_fields = ['duration_ms', 'memory_usage_mb', 'cpu_usage_percent']
        if any(hasattr(record, field) for field in performance_fields):
            record.performance_event = True
            return True
        
        # Check message content for performance keywords
        message = record.getMessage().lower()
        performance_keywords = ['slow', 'timeout', 'performance', 'duration', 'latency', 'response time']
        if any(keyword in message for keyword in performance_keywords):
            record.performance_event = True
            return True
        
        return False


class ErrorSeverityFilter(logging.Filter):
    """
    Filter and categorize errors by severity
    """
    
    # Critical error patterns
    CRITICAL_PATTERNS = [
        r'out of memory',
        r'disk.*full',
        r'database.*down',
        r'connection.*refused',
        r'service.*unavailable',
        r'system.*error'
    ]
    
    # High severity patterns
    HIGH_PATTERNS = [
        r'authentication.*failed',
        r'permission.*denied',
        r'data.*corruption',
        r'integrity.*error',
        r'timeout.*error'
    ]
    
    def __init__(self, min_severity: str = 'INFO'):
        super().__init__()
        self.min_level = getattr(logging, min_severity.upper(), logging.INFO)
        
        # Compile regex patterns
        self.critical_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.CRITICAL_PATTERNS]
        self.high_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.HIGH_PATTERNS]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and categorize errors by severity"""
        
        # Skip if below minimum level
        if record.levelno < self.min_level:
            return False
        
        message = record.getMessage()
        
        # Check for critical patterns
        if any(pattern.search(message) for pattern in self.critical_patterns):
            record.error_severity = 'critical'
            record.requires_immediate_attention = True
            return True
        
        # Check for high severity patterns
        if any(pattern.search(message) for pattern in self.high_patterns):
            record.error_severity = 'high'
            record.requires_escalation = True
            return True
        
        # Default severity based on log level
        if record.levelno >= logging.CRITICAL:
            record.error_severity = 'critical'
        elif record.levelno >= logging.ERROR:
            record.error_severity = 'high'
        elif record.levelno >= logging.WARNING:
            record.error_severity = 'medium'
        else:
            record.error_severity = 'low'
        
        return True


class SensitiveDataFilter(logging.Filter):
    """
    Filter to remove sensitive data from log records
    """
    
    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),  # Email addresses
        (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CARD]'),  # Credit card numbers
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]'),  # SSN
        (r'password["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'password: [REDACTED]'),  # Passwords
        (r'token["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'token: [REDACTED]'),  # Tokens
        (r'api_key["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'api_key: [REDACTED]'),  # API keys
        (r'secret["\']?\s*[:=]\s*["\']?([^"\'\s]+)', r'secret: [REDACTED]'),  # Secrets
    ]
    
    def __init__(self):
        super().__init__()
        # Compile patterns for better performance
        self.compiled_patterns = [(re.compile(pattern, re.IGNORECASE), replacement) 
                                for pattern, replacement in self.SENSITIVE_PATTERNS]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Remove sensitive data from log record"""
        
        # Sanitize message
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            for pattern, replacement in self.compiled_patterns:
                record.msg = pattern.sub(replacement, record.msg)
        
        # Sanitize args if present
        if hasattr(record, 'args') and record.args:
            sanitized_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    for pattern, replacement in self.compiled_patterns:
                        arg = pattern.sub(replacement, arg)
                sanitized_args.append(arg)
            record.args = tuple(sanitized_args)
        
        # Sanitize extra fields
        for field_name, field_value in record.__dict__.items():
            if isinstance(field_value, str) and not field_name.startswith('_'):
                for pattern, replacement in self.compiled_patterns:
                    sanitized_value = pattern.sub(replacement, field_value)
                    if sanitized_value != field_value:
                        setattr(record, field_name, sanitized_value)
        
        return True


class RateLimitFilter(logging.Filter):
    """
    Filter to rate limit log messages
    """
    
    def __init__(self, rate_limit: int = 100, time_window: int = 60):
        super().__init__()
        self.rate_limit = rate_limit
        self.time_window = time_window
        self.message_counts = {}
        
    def filter(self, record: logging.LogRecord) -> bool:
        """Rate limit log messages"""
        import time
        
        # Create a key for this message type
        key = f"{record.levelname}:{record.name}:{record.getMessage()[:100]}"
        current_time = int(time.time())
        
        # Clean old entries
        cutoff_time = current_time - self.time_window
        self.message_counts = {k: v for k, v in self.message_counts.items() 
                             if v['last_seen'] > cutoff_time}
        
        # Check rate limit
        if key in self.message_counts:
            self.message_counts[key]['count'] += 1
            self.message_counts[key]['last_seen'] = current_time
            
            if self.message_counts[key]['count'] > self.rate_limit:
                # Add suppression notice
                if self.message_counts[key]['count'] == self.rate_limit + 1:
                    record.msg = f"{record.msg} [Similar messages suppressed]"
                    return True
                else:
                    return False
        else:
            self.message_counts[key] = {'count': 1, 'last_seen': current_time}
        
        return True


class BusinessEventFilter(logging.Filter):
    """
    Filter for business-related events
    """
    
    BUSINESS_EVENT_TYPES = {
        'user_login', 'user_logout', 'deal_created', 'deal_updated', 'deal_deleted',
        'payment_processed', 'commission_calculated', 'client_created', 'client_updated'
    }
    
    BUSINESS_LOGGERS = {
        'business_events', 'user_actions', 'deal_management', 'payment_processing',
        'commission_calculation', 'client_management'
    }
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter business-related events"""
        
        # Check logger name
        if any(logger in record.name for logger in self.BUSINESS_LOGGERS):
            record.business_event = True
            return True
        
        # Check event type
        if hasattr(record, 'event_type') and record.event_type in self.BUSINESS_EVENT_TYPES:
            record.business_event = True
            return True
        
        # Check for business-related tags
        if hasattr(record, 'tags') and isinstance(record.tags, list):
            if any(tag in ['business_event', 'user_action', 'transaction'] for tag in record.tags):
                record.business_event = True
                return True
        
        return False


class DebugFilter(logging.Filter):
    """
    Filter for debug information in development
    """
    
    def __init__(self, debug_enabled: bool = True):
        super().__init__()
        self.debug_enabled = debug_enabled
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter debug records based on debug setting"""
        
        if not self.debug_enabled and record.levelno == logging.DEBUG:
            return False
        
        # Add debug context in debug mode
        if self.debug_enabled and record.levelno >= logging.WARNING:
            record.debug_context = True
            
            # Add more detailed information for errors in debug mode
            if record.exc_info:
                record.debug_traceback = True
        
        return True


# Filter registry
FILTERS = {
    'correlation': CorrelationFilter,
    'security': SecurityFilter,
    'performance': PerformanceFilter,
    'error_severity': ErrorSeverityFilter,
    'sensitive_data': SensitiveDataFilter,
    'rate_limit': RateLimitFilter,
    'business_event': BusinessEventFilter,
    'debug': DebugFilter,
}


def get_filter(filter_name: str, **kwargs) -> logging.Filter:
    """
    Get a filter by name with optional parameters
    """
    filter_class = FILTERS.get(filter_name)
    if not filter_class:
        raise ValueError(f"Unknown filter: {filter_name}")
    
    return filter_class(**kwargs)
