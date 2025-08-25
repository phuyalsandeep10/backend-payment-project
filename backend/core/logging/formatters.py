"""
Custom logging formatters for structured logging
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional


class StructuredJSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging with correlation and context
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        
        # Base log structure
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process': record.process,
            'thread': record.thread,
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else 'Unknown',
                'message': str(record.exc_info[1]) if record.exc_info[1] else '',
                'traceback': self.formatException(record.exc_info)
            }
        
        # Add correlation ID if present
        if hasattr(record, 'correlation_id') and record.correlation_id:
            log_entry['correlation_id'] = record.correlation_id
        
        # Add user context if present
        if hasattr(record, 'user_id') and record.user_id:
            log_entry['user_id'] = record.user_id
        
        # Add structured data if present
        if hasattr(record, 'structured') and record.structured:
            try:
                # If message is already JSON, parse it
                structured_data = json.loads(record.getMessage())
                log_entry.update(structured_data)
            except (json.JSONDecodeError, ValueError):
                # Not JSON, keep as regular message
                pass
        
        # Add extra fields from record
        for key, value in record.__dict__.items():
            if key not in log_entry and not key.startswith('_') and key not in [
                'name', 'msg', 'args', 'levelno', 'pathname', 'filename',
                'exc_info', 'exc_text', 'stack_info', 'created', 'msecs',
                'relativeCreated', 'getMessage', 'structured'
            ]:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=self._json_serializer, ensure_ascii=False)
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for complex objects"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return str(obj)
        else:
            return str(obj)


class StructuredConsoleFormatter(logging.Formatter):
    """
    Console formatter for structured logging with color coding
    """
    
    # Color codes for different log levels
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record for console with colors and structure"""
        
        # Get color for log level
        color = self.COLORS.get(record.levelname, '')
        reset = self.COLORS['RESET']
        
        # Base format with colors
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S.%f')[:-3]
        
        # Build formatted message
        parts = [
            f"{color}{record.levelname:<8}{reset}",
            f"{timestamp}",
            f"{record.name}",
        ]
        
        # Add correlation ID if present
        if hasattr(record, 'correlation_id') and record.correlation_id:
            parts.append(f"[{record.correlation_id[:8]}]")
        
        # Add user ID if present
        if hasattr(record, 'user_id') and record.user_id:
            parts.append(f"user:{record.user_id}")
        
        # Add event type if present
        if hasattr(record, 'event_type') and record.event_type:
            parts.append(f"event:{record.event_type}")
        
        # Main message
        parts.append(f"- {record.getMessage()}")
        
        # Add location info for errors
        if record.levelno >= logging.ERROR:
            parts.append(f"({record.module}:{record.lineno})")
        
        formatted_message = " ".join(parts)
        
        # Add exception info if present
        if record.exc_info and record.exc_text:
            formatted_message += f"\n{record.exc_text}"
        
        return formatted_message


class CompactJSONFormatter(logging.Formatter):
    """
    Compact JSON formatter for high-volume logs
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as compact JSON"""
        
        log_entry = {
            'ts': record.created,
            'lvl': record.levelname[0],  # First letter only
            'msg': record.getMessage(),
            'mod': record.module,
        }
        
        # Add correlation ID if present (shortened)
        if hasattr(record, 'correlation_id') and record.correlation_id:
            log_entry['cid'] = record.correlation_id[:8]
        
        # Add user ID if present
        if hasattr(record, 'user_id') and record.user_id:
            log_entry['uid'] = record.user_id
        
        # Add event type if present
        if hasattr(record, 'event_type') and record.event_type:
            log_entry['evt'] = record.event_type
        
        # Add exception type only (not full traceback)
        if record.exc_info and record.exc_info[0]:
            log_entry['exc'] = record.exc_info[0].__name__
        
        return json.dumps(log_entry, separators=(',', ':'))


class SecurityLogFormatter(logging.Formatter):
    """
    Specialized formatter for security logs
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format security log record with additional context"""
        
        timestamp = datetime.fromtimestamp(record.created).isoformat() + 'Z'
        
        security_entry = {
            'timestamp': timestamp,
            'level': record.levelname,
            'security_event': True,
            'message': record.getMessage(),
            'logger': record.name,
        }
        
        # Add security-specific fields
        security_fields = [
            'ip_address', 'user_id', 'session_id', 'event_type',
            'attack_type', 'detected_pattern', 'severity',
            'requires_blocking', 'requires_investigation'
        ]
        
        for field in security_fields:
            if hasattr(record, field):
                security_entry[field] = getattr(record, field)
        
        # Add correlation ID
        if hasattr(record, 'correlation_id') and record.correlation_id:
            security_entry['correlation_id'] = record.correlation_id
        
        # Add request context
        if hasattr(record, 'request_path'):
            security_entry['request'] = {
                'path': getattr(record, 'request_path', ''),
                'method': getattr(record, 'request_method', ''),
                'user_agent': getattr(record, 'user_agent', ''),
            }
        
        # Add geolocation if available
        if hasattr(record, 'country') or hasattr(record, 'city'):
            security_entry['location'] = {
                'country': getattr(record, 'country', ''),
                'city': getattr(record, 'city', ''),
                'region': getattr(record, 'region', ''),
            }
        
        return json.dumps(security_entry, default=str, ensure_ascii=False)


class PerformanceLogFormatter(logging.Formatter):
    """
    Specialized formatter for performance logs
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format performance log record with metrics"""
        
        timestamp = datetime.fromtimestamp(record.created).isoformat() + 'Z'
        
        perf_entry = {
            'timestamp': timestamp,
            'level': record.levelname,
            'performance_event': True,
            'message': record.getMessage(),
            'logger': record.name,
        }
        
        # Add performance-specific fields
        performance_fields = [
            'duration_ms', 'memory_usage_mb', 'cpu_usage_percent',
            'operation', 'threshold_ms', 'status_code', 'content_length',
            'query_count', 'cache_hits', 'cache_misses'
        ]
        
        for field in performance_fields:
            if hasattr(record, field):
                perf_entry[field] = getattr(record, field)
        
        # Add correlation ID
        if hasattr(record, 'correlation_id') and record.correlation_id:
            perf_entry['correlation_id'] = record.correlation_id
        
        # Add request context
        if hasattr(record, 'request_path'):
            perf_entry['request'] = {
                'path': getattr(record, 'request_path', ''),
                'method': getattr(record, 'request_method', ''),
            }
        
        # Add threshold analysis
        if hasattr(record, 'duration_ms') and hasattr(record, 'threshold_ms'):
            perf_entry['performance_analysis'] = {
                'threshold_exceeded': record.duration_ms > record.threshold_ms,
                'slowness_factor': record.duration_ms / record.threshold_ms if record.threshold_ms > 0 else 0,
                'performance_category': self._categorize_performance(record.duration_ms)
            }
        
        return json.dumps(perf_entry, default=str, ensure_ascii=False)
    
    def _categorize_performance(self, duration_ms: float) -> str:
        """Categorize performance based on duration"""
        if duration_ms < 100:
            return 'fast'
        elif duration_ms < 500:
            return 'normal'
        elif duration_ms < 1000:
            return 'slow'
        elif duration_ms < 5000:
            return 'very_slow'
        else:
            return 'critical'


class ErrorCorrelationFormatter(logging.Formatter):
    """
    Specialized formatter for error correlation logs
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format error correlation log with cluster information"""
        
        timestamp = datetime.fromtimestamp(record.created).isoformat() + 'Z'
        
        correlation_entry = {
            'timestamp': timestamp,
            'level': record.levelname,
            'correlation_event': True,
            'message': record.getMessage(),
            'logger': record.name,
        }
        
        # Add correlation-specific fields
        correlation_fields = [
            'signature_hash', 'error_type', 'error_location', 'error_pattern',
            'occurrence_count', 'unique_users', 'unique_ips', 'severity_level',
            'first_occurrence', 'pattern_analysis', 'impact_score'
        ]
        
        for field in correlation_fields:
            if hasattr(record, field):
                correlation_entry[field] = getattr(record, field)
        
        # Add correlation ID
        if hasattr(record, 'correlation_id') and record.correlation_id:
            correlation_entry['correlation_id'] = record.correlation_id
        
        # Add cluster metadata
        if hasattr(record, 'cluster_info'):
            correlation_entry['cluster'] = record.cluster_info
        
        # Add trending information
        if hasattr(record, 'recent_count'):
            correlation_entry['trending'] = {
                'recent_occurrences': record.recent_count,
                'is_spike': getattr(record, 'is_spike', False),
                'trend_direction': getattr(record, 'trend_direction', 'stable')
            }
        
        return json.dumps(correlation_entry, default=str, ensure_ascii=False)


# Formatter registry for easy access
FORMATTERS = {
    'json': StructuredJSONFormatter,
    'console': StructuredConsoleFormatter,
    'compact': CompactJSONFormatter,
    'security': SecurityLogFormatter,
    'performance': PerformanceLogFormatter,
    'correlation': ErrorCorrelationFormatter,
}


def get_formatter(formatter_name: str, **kwargs) -> logging.Formatter:
    """
    Get a formatter by name with optional parameters
    """
    formatter_class = FORMATTERS.get(formatter_name, StructuredJSONFormatter)
    return formatter_class(**kwargs)
