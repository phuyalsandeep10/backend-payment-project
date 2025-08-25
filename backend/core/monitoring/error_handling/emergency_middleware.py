"""
Emergency Response Middleware

This middleware provides emergency response handling for critical system failures,
particularly focusing on authentication failures and middleware stack issues.

Requirements addressed:
- 3.4: Emergency response generation for critical errors
- 4.1: Circuit breaker pattern for repeated middleware failures
"""

import logging
import time
from typing import Optional
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.template.response import ContentNotRenderedError
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError, OperationalError
from rest_framework.response import Response
from .emergency_response_system import emergency_system, EmergencyResponseGenerator

logger = logging.getLogger(__name__)


class EmergencyResponseMiddleware(MiddlewareMixin):
    """
    Middleware that provides emergency response handling for critical failures
    
    This middleware should be positioned early in the middleware stack to catch
    failures from other middleware components.
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.emergency_generator = EmergencyResponseGenerator()
        self.failure_count = 0
        self.last_health_check = 0
        self.health_check_interval = 60  # Check health every 60 seconds
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming request and check system health
        """
        # Add request ID for tracking
        if not hasattr(request, 'request_id'):
            import uuid
            request.request_id = str(uuid.uuid4())
        
        # Periodic health checks
        current_time = time.time()
        if current_time - self.last_health_check > self.health_check_interval:
            self._run_health_checks()
            self.last_health_check = current_time
        
        # Check if any critical circuit breakers are open
        auth_breaker = emergency_system.get_circuit_breaker('authentication')
        if auth_breaker.state.value == 'open' and request.path.startswith('/api/auth/'):
            logger.warning(f"Authentication circuit breaker is open, blocking request to {request.path}")
            return self.emergency_generator.generate_emergency_response(
                'circuit_breaker_open',
                status_code=503,
                request_id=request.request_id,
                additional_context={
                    'blocked_endpoint': request.path,
                    'circuit_breaker': 'authentication'
                }
            )
        
        return None
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Process response and handle any rendering issues
        """
        try:
            # Check for ContentNotRenderedError issues
            if hasattr(response, 'is_rendered') and not response.is_rendered:
                logger.warning("Unrendered response detected, forcing render")
                try:
                    response.render()
                except Exception as render_error:
                    logger.error(f"Failed to render response: {render_error}")
                    return self._handle_rendering_failure(request, render_error)
            
            # Check response status for potential issues
            if response.status_code >= 500:
                self._record_server_error(request, response)
            
            return response
            
        except ContentNotRenderedError as e:
            logger.error(f"ContentNotRenderedError in emergency middleware: {e}")
            return self._handle_rendering_failure(request, e)
        except Exception as e:
            logger.error(f"Unexpected error in emergency response middleware: {e}")
            return self._handle_critical_failure(request, e)
    
    def process_exception(self, request: HttpRequest, exception: Exception) -> Optional[HttpResponse]:
        """
        Handle exceptions that occur during request processing
        """
        logger.error(f"Exception caught by emergency middleware: {type(exception).__name__}: {exception}")
        
        # Handle specific exception types
        if isinstance(exception, ContentNotRenderedError):
            return self._handle_rendering_failure(request, exception)
        elif isinstance(exception, (DatabaseError, OperationalError)):
            return self._handle_database_failure(request, exception)
        elif isinstance(exception, ImproperlyConfigured):
            return self._handle_configuration_failure(request, exception)
        else:
            return self._handle_critical_failure(request, exception)
    
    def _handle_rendering_failure(self, request: HttpRequest, error: Exception) -> HttpResponse:
        """
        Handle ContentNotRenderedError and other rendering failures
        """
        logger.error(f"Rendering failure on {request.path}: {error}")
        
        # Record failure in circuit breaker
        middleware_breaker = emergency_system.get_circuit_breaker('middleware')
        try:
            # Simulate failure to trigger circuit breaker
            def failing_operation():
                raise error
            middleware_breaker.call(failing_operation)
        except:
            pass  # Expected to fail
        
        # Generate emergency response
        return self.emergency_generator.generate_emergency_response(
            'middleware_failure',
            status_code=500,
            request_id=getattr(request, 'request_id', None),
            additional_context={
                'error_type': 'rendering_failure',
                'endpoint': request.path,
                'method': request.method,
                'error_details': str(error)
            }
        )
    
    def _handle_database_failure(self, request: HttpRequest, error: Exception) -> HttpResponse:
        """
        Handle database connection and operation failures
        """
        logger.error(f"Database failure on {request.path}: {error}")
        
        # Record failure in database circuit breaker
        db_breaker = emergency_system.get_circuit_breaker('database')
        try:
            def failing_operation():
                raise error
            db_breaker.call(failing_operation)
        except:
            pass  # Expected to fail
        
        # Update system health
        emergency_system.update_system_health('database', False)
        
        return self.emergency_generator.generate_emergency_response(
            'database_failure',
            status_code=503,
            request_id=getattr(request, 'request_id', None),
            additional_context={
                'error_type': 'database_failure',
                'endpoint': request.path,
                'method': request.method,
                'error_details': str(error)
            }
        )
    
    def _handle_configuration_failure(self, request: HttpRequest, error: Exception) -> HttpResponse:
        """
        Handle configuration and setup failures
        """
        logger.critical(f"Configuration failure on {request.path}: {error}")
        
        return self.emergency_generator.generate_emergency_response(
            'critical_system_failure',
            status_code=500,
            request_id=getattr(request, 'request_id', None),
            additional_context={
                'error_type': 'configuration_failure',
                'endpoint': request.path,
                'method': request.method,
                'error_details': str(error)
            }
        )
    
    def _handle_critical_failure(self, request: HttpRequest, error: Exception) -> HttpResponse:
        """
        Handle critical system failures
        """
        logger.critical(f"Critical failure on {request.path}: {error}")
        self.failure_count += 1
        
        return self.emergency_generator.generate_emergency_response(
            'critical_system_failure',
            status_code=500,
            request_id=getattr(request, 'request_id', None),
            additional_context={
                'error_type': 'critical_failure',
                'endpoint': request.path,
                'method': request.method,
                'failure_count': self.failure_count,
                'error_details': str(error)
            }
        )
    
    def _record_server_error(self, request: HttpRequest, response: HttpResponse):
        """
        Record server errors for monitoring
        """
        if response.status_code >= 500:
            logger.warning(f"Server error {response.status_code} on {request.path}")
            
            # Record in appropriate circuit breaker based on endpoint
            if request.path.startswith('/api/auth/'):
                auth_breaker = emergency_system.get_circuit_breaker('authentication')
                try:
                    def failing_operation():
                        raise Exception(f"HTTP {response.status_code}")
                    auth_breaker.call(failing_operation)
                except:
                    pass  # Expected to fail
    
    def _run_health_checks(self):
        """
        Run periodic health checks
        """
        try:
            from .emergency_response_system import run_health_checks
            run_health_checks()
        except Exception as e:
            logger.error(f"Health check failed: {e}")


class AuthenticationEmergencyMiddleware(MiddlewareMixin):
    """
    Specialized middleware for authentication emergency responses
    
    This middleware specifically handles authentication-related failures
    and should be positioned after authentication middleware.
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.auth_failure_count = 0
    
    def process_exception(self, request: HttpRequest, exception: Exception) -> Optional[HttpResponse]:
        """
        Handle authentication-specific exceptions
        """
        # Only handle authentication-related requests
        if not request.path.startswith('/api/auth/'):
            return None
        
        logger.error(f"Authentication exception on {request.path}: {type(exception).__name__}: {exception}")
        
        # Use emergency system to handle authentication failure
        return emergency_system.handle_authentication_failure(request, exception)
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Monitor authentication responses
        """
        # Only monitor authentication endpoints
        if not request.path.startswith('/api/auth/'):
            return response
        
        # Check for authentication failures
        if response.status_code in [401, 403, 500]:
            self.auth_failure_count += 1
            logger.warning(f"Authentication failure {response.status_code} on {request.path} (count: {self.auth_failure_count})")
            
            # If we have too many failures, the circuit breaker will handle it
            auth_breaker = emergency_system.get_circuit_breaker('authentication')
            if response.status_code == 500:
                try:
                    def failing_operation():
                        raise Exception(f"Authentication HTTP {response.status_code}")
                    auth_breaker.call(failing_operation)
                except:
                    pass  # Expected to fail, will trigger circuit breaker
        
        return response


class CircuitBreakerStatusMiddleware(MiddlewareMixin):
    """
    Middleware to add circuit breaker status to responses (for debugging)
    """
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Add circuit breaker status headers for debugging
        """
        # Only add headers in debug mode
        from django.conf import settings
        if settings.DEBUG:
            system_status = emergency_system.get_system_status()
            
            # Add headers for circuit breaker states
            for name, breaker_status in system_status['circuit_breakers'].items():
                header_name = f'X-Circuit-Breaker-{name.title()}'
                response[header_name] = breaker_status['state']
            
            # Add overall system health
            response['X-System-Health'] = 'healthy' if system_status['system_health']['overall'] else 'degraded'
        
        return response


def emergency_response_decorator(component: str = 'general'):
    """
    Decorator to add emergency response handling to view functions
    """
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            try:
                return view_func(request, *args, **kwargs)
            except Exception as e:
                logger.error(f"View function {view_func.__name__} failed: {e}")
                
                if component == 'authentication':
                    return emergency_system.handle_authentication_failure(request, e)
                elif component == 'database':
                    return emergency_system.handle_database_failure(request, e)
                else:
                    return emergency_system.handle_middleware_failure(request, e)
        
        return wrapper
    return decorator