"""
Response Processing Monitor
Specialized monitoring for response type detection, rendering, and ContentNotRenderedError tracking
"""

from django.utils import timezone
from django.conf import settings
from datetime import timedelta, datetime
from typing import Dict, List, Optional, Any
import time
import logging
import threading
from collections import defaultdict, deque
from functools import wraps
import traceback

# Response processing logger
response_logger = logging.getLogger('response_processing')

class ResponseProcessingMonitor:
    """
    Specialized monitoring for response processing, template rendering, and error tracking
    """
    
    # Singleton instance
    _instance = None
    _lock = threading.Lock()
    
    # Monitoring configuration
    METRICS_RETENTION_HOURS = 24
    SLOW_RENDER_THRESHOLD = 0.5  # seconds
    ERROR_ALERT_THRESHOLD = 5  # errors per minute
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize response processing monitoring data structures"""
        # Response type tracking
        self.response_type_metrics = deque(maxlen=10000)  # Last 10k responses
        self.template_render_metrics = deque(maxlen=5000)  # Last 5k template renders
        self.content_not_rendered_errors = deque(maxlen=1000)  # Last 1k CNR errors
        
        # Error tracking by type
        self.error_counts = defaultdict(int)
        self.error_details = deque(maxlen=2000)  # Last 2k errors
        
        # Performance counters
        self.total_responses = 0
        self.template_responses = 0
        self.drf_responses = 0
        self.http_responses = 0
        self.render_errors = 0
        self.content_not_rendered_count = 0
        
        # Success rates
        self.successful_renders = 0
        self.failed_renders = 0
        
        response_logger.info("Response Processing Monitor initialized")
    
    def record_response_type(self, response_type: str, endpoint: str, method: str,
                           status_code: int, render_time: Optional[float] = None,
                           user_id: Optional[int] = None, organization_id: Optional[int] = None):
        """Record response type detection and processing"""
        self.total_responses += 1
        
        # Count by response type
        if response_type == 'TemplateResponse':
            self.template_responses += 1
        elif response_type == 'DRFResponse':
            self.drf_responses += 1
        elif response_type == 'HttpResponse':
            self.http_responses += 1
        
        response_metric = {
            'timestamp': timezone.now().isoformat(),
            'response_type': response_type,
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'render_time': render_time,
            'user_id': user_id,
            'organization_id': organization_id,
            'is_slow_render': render_time and render_time > self.SLOW_RENDER_THRESHOLD
        }
        
        self.response_type_metrics.append(response_metric)
        
        # Log slow renders
        if render_time and render_time > self.SLOW_RENDER_THRESHOLD:
            response_logger.warning(
                f"Slow response rendering: {render_time:.3f}s - {response_type} for {method} {endpoint}"
            )
    
    def record_template_render(self, template_name: str, render_time: float,
                             success: bool, error_message: Optional[str] = None,
                             context_size: Optional[int] = None):
        """Record template rendering performance and success"""
        if success:
            self.successful_renders += 1
        else:
            self.failed_renders += 1
            self.render_errors += 1
        
        render_metric = {
            'timestamp': timezone.now().isoformat(),
            'template_name': template_name,
            'render_time': render_time,
            'success': success,
            'error_message': error_message,
            'context_size': context_size,
            'is_slow': render_time > self.SLOW_RENDER_THRESHOLD
        }
        
        self.template_render_metrics.append(render_metric)
        
        # Log render failures
        if not success:
            response_logger.error(
                f"Template render failed: {template_name} - {error_message}"
            )
        elif render_time > self.SLOW_RENDER_THRESHOLD:
            response_logger.warning(
                f"Slow template render: {template_name} - {render_time:.3f}s"
            )
    
    def record_content_not_rendered_error(self, endpoint: str, method: str,
                                        middleware_name: str, stack_trace: str,
                                        user_id: Optional[int] = None,
                                        organization_id: Optional[int] = None):
        """Record ContentNotRenderedError occurrences"""
        self.content_not_rendered_count += 1
        self.error_counts['ContentNotRenderedError'] += 1
        
        error_record = {
            'timestamp': timezone.now().isoformat(),
            'error_type': 'ContentNotRenderedError',
            'endpoint': endpoint,
            'method': method,
            'middleware_name': middleware_name,
            'stack_trace': stack_trace,
            'user_id': user_id,
            'organization_id': organization_id
        }
        
        self.content_not_rendered_errors.append(error_record)
        self.error_details.append(error_record)
        
        # Log critical error
        response_logger.critical(
            f"ContentNotRenderedError in {middleware_name}: {method} {endpoint}"
        )
        
        # Check if we need to trigger an alert
        self._check_error_alert_threshold('ContentNotRenderedError')
    
    def record_response_processing_error(self, error_type: str, endpoint: str,
                                       method: str, error_message: str,
                                       stack_trace: str, user_id: Optional[int] = None,
                                       organization_id: Optional[int] = None):
        """Record general response processing errors"""
        self.error_counts[error_type] += 1
        
        error_record = {
            'timestamp': timezone.now().isoformat(),
            'error_type': error_type,
            'endpoint': endpoint,
            'method': method,
            'error_message': error_message,
            'stack_trace': stack_trace,
            'user_id': user_id,
            'organization_id': organization_id
        }
        
        self.error_details.append(error_record)
        
        # Log error with appropriate level
        if error_type in ['ContentNotRenderedError', 'TemplateDoesNotExist']:
            response_logger.critical(f"{error_type}: {method} {endpoint} - {error_message}")
        else:
            response_logger.error(f"{error_type}: {method} {endpoint} - {error_message}")
        
        # Check if we need to trigger an alert
        self._check_error_alert_threshold(error_type)
    
    def _check_error_alert_threshold(self, error_type: str):
        """Check if error rate exceeds alert threshold"""
        # Count errors of this type in the last minute
        one_minute_ago = (timezone.now() - timedelta(minutes=1)).isoformat()
        recent_errors = [
            error for error in self.error_details
            if error['error_type'] == error_type and error['timestamp'] >= one_minute_ago
        ]
        
        if len(recent_errors) >= self.ERROR_ALERT_THRESHOLD:
            response_logger.critical(
                f"ERROR ALERT: {error_type} occurred {len(recent_errors)} times in the last minute"
            )
    
    def get_response_type_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get response type distribution summary"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        cutoff_str = cutoff_time.isoformat()
        
        # Filter metrics by time
        recent_responses = [
            r for r in self.response_type_metrics 
            if r['timestamp'] >= cutoff_str
        ]
        
        if not recent_responses:
            return {
                'period_hours': hours,
                'total_responses': 0,
                'response_types': {},
                'render_performance': {}
            }
        
        # Count by response type
        type_counts = defaultdict(int)
        render_times = []
        slow_renders = 0
        
        for response in recent_responses:
            type_counts[response['response_type']] += 1
            if response['render_time']:
                render_times.append(response['render_time'])
                if response['is_slow_render']:
                    slow_renders += 1
        
        # Calculate render performance
        render_performance = {}
        if render_times:
            render_performance = {
                'avg_render_time': sum(render_times) / len(render_times),
                'min_render_time': min(render_times),
                'max_render_time': max(render_times),
                'slow_renders': slow_renders,
                'slow_render_rate': (slow_renders / len(render_times)) * 100
            }
        
        return {
            'period_hours': hours,
            'total_responses': len(recent_responses),
            'response_types': dict(type_counts),
            'render_performance': render_performance,
            'success_rate': ((len(recent_responses) - slow_renders) / len(recent_responses)) * 100 if recent_responses else 100
        }
    
    def get_template_render_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get template rendering performance summary"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        cutoff_str = cutoff_time.isoformat()
        
        # Filter template metrics by time
        recent_renders = [
            r for r in self.template_render_metrics 
            if r['timestamp'] >= cutoff_str
        ]
        
        if not recent_renders:
            return {
                'period_hours': hours,
                'total_renders': 0,
                'success_rate': 100,
                'performance': {}
            }
        
        # Calculate statistics
        successful = [r for r in recent_renders if r['success']]
        failed = [r for r in recent_renders if not r['success']]
        render_times = [r['render_time'] for r in recent_renders]
        slow_renders = [r for r in recent_renders if r['is_slow']]
        
        # Group by template
        template_stats = defaultdict(lambda: {'count': 0, 'failures': 0, 'total_time': 0})
        for render in recent_renders:
            template_name = render['template_name']
            template_stats[template_name]['count'] += 1
            template_stats[template_name]['total_time'] += render['render_time']
            if not render['success']:
                template_stats[template_name]['failures'] += 1
        
        # Calculate averages for templates
        for template, stats in template_stats.items():
            stats['avg_time'] = stats['total_time'] / stats['count']
            stats['failure_rate'] = (stats['failures'] / stats['count']) * 100
            del stats['total_time']  # Remove intermediate calculation
        
        return {
            'period_hours': hours,
            'total_renders': len(recent_renders),
            'successful_renders': len(successful),
            'failed_renders': len(failed),
            'success_rate': (len(successful) / len(recent_renders)) * 100,
            'performance': {
                'avg_render_time': sum(render_times) / len(render_times),
                'min_render_time': min(render_times),
                'max_render_time': max(render_times),
                'slow_renders': len(slow_renders),
                'slow_render_rate': (len(slow_renders) / len(recent_renders)) * 100
            },
            'by_template': dict(template_stats)
        }
    
    def get_error_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get error occurrence summary"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        cutoff_str = cutoff_time.isoformat()
        
        # Filter errors by time
        recent_errors = [
            e for e in self.error_details 
            if e['timestamp'] >= cutoff_str
        ]
        
        # Count by error type
        error_type_counts = defaultdict(int)
        endpoint_errors = defaultdict(int)
        
        for error in recent_errors:
            error_type_counts[error['error_type']] += 1
            endpoint_key = f"{error['method']} {error['endpoint']}"
            endpoint_errors[endpoint_key] += 1
        
        # Get ContentNotRenderedError details
        cnr_errors = [
            e for e in recent_errors 
            if e['error_type'] == 'ContentNotRenderedError'
        ]
        
        return {
            'period_hours': hours,
            'total_errors': len(recent_errors),
            'content_not_rendered_errors': len(cnr_errors),
            'error_types': dict(error_type_counts),
            'errors_by_endpoint': dict(endpoint_errors),
            'cnr_error_details': cnr_errors[-10:] if cnr_errors else [],  # Last 10 CNR errors
            'error_rate_per_hour': len(recent_errors) / hours if hours > 0 else 0
        }
    
    def get_performance_metrics(self, hours: int = 1) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""
        return {
            'response_types': self.get_response_type_summary(hours),
            'template_rendering': self.get_template_render_summary(hours),
            'errors': self.get_error_summary(hours),
            'overall_stats': {
                'total_responses': self.total_responses,
                'template_responses': self.template_responses,
                'drf_responses': self.drf_responses,
                'http_responses': self.http_responses,
                'render_errors': self.render_errors,
                'content_not_rendered_count': self.content_not_rendered_count,
                'render_success_rate': (self.successful_renders / (self.successful_renders + self.failed_renders)) * 100 if (self.successful_renders + self.failed_renders) > 0 else 100
            }
        }
    
    def get_recent_content_not_rendered_errors(self, limit: int = 50) -> List[Dict]:
        """Get recent ContentNotRenderedError occurrences"""
        return list(self.content_not_rendered_errors)[-limit:]
    
    def get_slow_renders(self, limit: int = 50) -> List[Dict]:
        """Get slowest response renders"""
        all_renders = []
        
        # Collect from response metrics
        for response in self.response_type_metrics:
            if response['render_time'] and response['is_slow_render']:
                all_renders.append({
                    'timestamp': response['timestamp'],
                    'type': 'response',
                    'name': f"{response['method']} {response['endpoint']}",
                    'render_time': response['render_time'],
                    'response_type': response['response_type']
                })
        
        # Collect from template metrics
        for template in self.template_render_metrics:
            if template['is_slow']:
                all_renders.append({
                    'timestamp': template['timestamp'],
                    'type': 'template',
                    'name': template['template_name'],
                    'render_time': template['render_time'],
                    'success': template['success']
                })
        
        # Sort by render time and return top results
        return sorted(all_renders, key=lambda x: x['render_time'], reverse=True)[:limit]
    
    def clear_old_metrics(self):
        """Clear old metrics to prevent memory buildup"""
        cutoff_time = timezone.now() - timedelta(hours=self.METRICS_RETENTION_HOURS)
        cutoff_str = cutoff_time.isoformat()
        
        # Clear old response metrics
        self.response_type_metrics = deque(
            [r for r in self.response_type_metrics if r['timestamp'] >= cutoff_str],
            maxlen=10000
        )
        
        # Clear old template metrics
        self.template_render_metrics = deque(
            [t for t in self.template_render_metrics if t['timestamp'] >= cutoff_str],
            maxlen=5000
        )
        
        # Clear old error details
        self.error_details = deque(
            [e for e in self.error_details if e['timestamp'] >= cutoff_str],
            maxlen=2000
        )
        
        # Clear old CNR errors
        self.content_not_rendered_errors = deque(
            [e for e in self.content_not_rendered_errors if e['timestamp'] >= cutoff_str],
            maxlen=1000
        )
        
        response_logger.info("Cleared old response processing metrics")


# Decorator for monitoring response processing
def monitor_response_processing(func):
    """Decorator to monitor response processing in views and middleware"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        monitor = ResponseProcessingMonitor()
        
        try:
            response = func(*args, **kwargs)
            render_time = time.time() - start_time
            
            # Determine response type
            response_type = type(response).__name__
            
            # Extract request info if available
            request = None
            if args and hasattr(args[0], 'path'):
                request = args[0]
            elif args and hasattr(args[0], 'request'):
                request = args[0].request
            
            if request:
                endpoint = request.path
                method = request.method
                status_code = getattr(response, 'status_code', 200)
                
                # Get user info
                user_id = None
                organization_id = None
                if hasattr(request, 'user') and request.user.is_authenticated:
                    user_id = request.user.id
                    if hasattr(request.user, 'organization') and request.user.organization is not None:
                        organization_id = request.user.organization.id
                
                monitor.record_response_type(
                    response_type=response_type,
                    endpoint=endpoint,
                    method=method,
                    status_code=status_code,
                    render_time=render_time,
                    user_id=user_id,
                    organization_id=organization_id
                )
            
            return response
            
        except Exception as e:
            render_time = time.time() - start_time
            error_type = type(e).__name__
            
            # Extract request info for error logging
            request = None
            if args and hasattr(args[0], 'path'):
                request = args[0]
            elif args and hasattr(args[0], 'request'):
                request = args[0].request
            
            if request:
                endpoint = request.path
                method = request.method
                
                # Get user info
                user_id = None
                organization_id = None
                if hasattr(request, 'user') and request.user.is_authenticated:
                    user_id = request.user.id
                    if hasattr(request.user, 'organization') and request.user.organization is not None:
                        organization_id = request.user.organization.id
                
                # Special handling for ContentNotRenderedError
                if error_type == 'ContentNotRenderedError':
                    monitor.record_content_not_rendered_error(
                        endpoint=endpoint,
                        method=method,
                        middleware_name=func.__name__,
                        stack_trace=traceback.format_exc(),
                        user_id=user_id,
                        organization_id=organization_id
                    )
                else:
                    monitor.record_response_processing_error(
                        error_type=error_type,
                        endpoint=endpoint,
                        method=method,
                        error_message=str(e),
                        stack_trace=traceback.format_exc(),
                        user_id=user_id,
                        organization_id=organization_id
                    )
            
            raise  # Re-raise the exception
    
    return wrapper


# Global response processing monitor instance
response_processing_monitor = ResponseProcessingMonitor()