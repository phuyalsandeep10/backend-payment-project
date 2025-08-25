"""
Simplified Exception Middleware for PRS Backend
Focused middleware that integrates with existing monitoring systems
"""

import time
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

from .structured_logger import (
    correlation_id_var, 
    user_context_var, 
    request_context_var,
    get_correlation_id
)
from .error_correlation import error_tracker
from .exception_handlers import (
    ExceptionClassifier,
    ResponseBuilder, 
    ExceptionLogger,
    CriticalPatternDetector
)
from ..monitoring.performance_monitor import PerformanceMonitor
from ..security.security_monitoring import SuspiciousActivityDetector


class ExceptionHandlerMiddleware(MiddlewareMixin):
    """
    Simplified exception middleware focused on core exception handling
    Integrates with existing monitoring systems
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.exception_logger = ExceptionLogger()
        self.critical_detector = CriticalPatternDetector()
        super().__init__(get_response)
    
    def process_exception(self, request, exception):
        """
        Process unhandled exceptions with comprehensive logging and correlation
        """
        # Get correlation and context information
        correlation_id = get_correlation_id()
        user_context = user_context_var.get({})
        
        # Extract request information efficiently
        request_info = self._extract_request_info(request)
        
        # Track error in correlation system
        error_cluster = error_tracker.track_error(
            error=exception,
            correlation_id=correlation_id,
            user_id=user_context.get('user_id'),
            organization_id=user_context.get('organization_id'),
            request_path=request.path,
            request_method=request.method,
            ip_address=request_info['ip_address'],
            context_data={
                'request_info': request_info,
                'user_context': user_context,
                'view_name': self._get_view_name(request),
            }
        )
        
        # Create appropriate response
        error_response = ResponseBuilder.create_error_response(exception, correlation_id)
        
        # Log the exception with structured logging
        self.exception_logger.log_exception(
            exception=exception,
            request=request,
            error_response=error_response,
            error_cluster=error_cluster,
            correlation_id=correlation_id
        )
        
        # Check for critical patterns
        self.critical_detector.check_critical_patterns(exception, error_cluster)
        
        return JsonResponse(
            error_response.to_dict(),
            status=error_response.status_code,
            headers={'X-Correlation-ID': correlation_id} if correlation_id else {}
        )
    
    def _extract_request_info(self, request) -> dict:
        """Extract request information efficiently"""
        request_info = {
            'method': request.method,
            'path': request.path,
            'query_params': dict(request.GET),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'ip_address': self._get_client_ip(request),
            'content_type': request.META.get('CONTENT_TYPE', ''),
        }
        
        # Add request body for POST/PUT/PATCH (if small enough and not binary)
        if request.method in ['POST', 'PUT', 'PATCH'] and hasattr(request, 'body'):
            try:
                body_size = len(request.body)
                if body_size < 1024 and request.META.get('CONTENT_TYPE', '').startswith('application/json'):
                    request_info['body'] = request.body.decode('utf-8')[:500]
                else:
                    request_info['body_size'] = body_size
            except:
                pass
        
        return request_info
    
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
    
    def _get_client_ip(self, request) -> str:
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip


class IntegratedMonitoringMiddleware(MiddlewareMixin):
    """
    Lightweight middleware that integrates with existing monitoring systems
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.performance_monitor = PerformanceMonitor()
        self.security_detector = SuspiciousActivityDetector()
        super().__init__(get_response)
    
    def process_request(self, request):
        """Initialize monitoring for request"""
        # Record start time for performance monitoring
        request._start_time = time.time()
        
        # Security monitoring for suspicious patterns
        if hasattr(self.security_detector, 'analyze_request'):
            user = getattr(request, 'user', None) if hasattr(request, 'user') else None
            self.security_detector.analyze_request(request, user)
        
        return None
    
    def process_response(self, request, response):
        """Complete monitoring for request"""
        # Performance monitoring
        if hasattr(request, '_start_time'):
            duration = time.time() - request._start_time
            
            # Use existing performance monitor
            if hasattr(self.performance_monitor, 'record_api_call'):
                self.performance_monitor.record_api_call(
                    endpoint=request.path,
                    method=request.method,
                    duration=duration,
                    status_code=response.status_code,
                    user_id=getattr(request.user, 'id', None) if hasattr(request, 'user') and request.user.is_authenticated else None
                )
        
        return response
