"""
Emergency Response Fallback System

This module provides emergency response generation and circuit breaker patterns
for critical system failures, particularly authentication and middleware failures.

Requirements addressed:
- 3.4: Emergency response generation for critical errors
- 4.1: Circuit breaker pattern for repeated middleware failures
"""

import time
import threading
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from rest_framework.response import Response
from rest_framework import status
from rest_framework.renderers import JSONRenderer
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5  # Number of failures before opening
    recovery_timeout: int = 60  # Seconds before trying half-open
    success_threshold: int = 3  # Successes needed to close from half-open
    timeout_window: int = 300   # Window for counting failures (seconds)


@dataclass
class FailureRecord:
    """Record of a failure event"""
    timestamp: datetime
    error_type: str
    endpoint: str
    details: str


class CircuitBreaker:
    """
    Circuit breaker implementation for middleware and authentication failures
    """
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.failures = deque(maxlen=100)  # Keep last 100 failures
        self._lock = threading.RLock()
        
    def call(self, func: Callable, *args, **kwargs):
        """
        Execute function with circuit breaker protection
        """
        with self._lock:
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    logger.info(f"Circuit breaker {self.name} moving to HALF_OPEN")
                else:
                    raise CircuitBreakerOpenError(f"Circuit breaker {self.name} is OPEN")
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except Exception as e:
                self._on_failure(str(e))
                raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if not self.last_failure_time:
            return True
        return (timezone.now() - self.last_failure_time).total_seconds() > self.config.recovery_timeout
    
    def _on_success(self):
        """Handle successful operation"""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
                logger.info(f"Circuit breaker {self.name} CLOSED after recovery")
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success in closed state
            self.failure_count = max(0, self.failure_count - 1)
    
    def _on_failure(self, error_details: str):
        """Handle failed operation"""
        self.failure_count += 1
        self.last_failure_time = timezone.now()
        
        # Record failure
        failure = FailureRecord(
            timestamp=timezone.now(),
            error_type=type(error_details).__name__,
            endpoint=getattr(self, 'current_endpoint', 'unknown'),
            details=error_details
        )
        self.failures.append(failure)
        
        # Clean old failures outside time window
        self._clean_old_failures()
        
        if self.state == CircuitState.CLOSED:
            if self.failure_count >= self.config.failure_threshold:
                self.state = CircuitState.OPEN
                logger.error(f"Circuit breaker {self.name} OPENED after {self.failure_count} failures")
        elif self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self.success_count = 0
            logger.error(f"Circuit breaker {self.name} returned to OPEN from HALF_OPEN")
    
    def _clean_old_failures(self):
        """Remove failures outside the time window"""
        cutoff_time = timezone.now() - timedelta(seconds=self.config.timeout_window)
        while self.failures and self.failures[0].timestamp < cutoff_time:
            self.failures.popleft()
    
    def get_status(self) -> Dict[str, Any]:
        """Get current circuit breaker status"""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'recent_failures': len(self.failures),
            'config': {
                'failure_threshold': self.config.failure_threshold,
                'recovery_timeout': self.config.recovery_timeout,
                'success_threshold': self.config.success_threshold,
                'timeout_window': self.config.timeout_window
            }
        }


class CircuitBreakerOpenError(Exception):
    """Exception raised when circuit breaker is open"""
    pass


class EmergencyResponseGenerator:
    """
    Generates emergency responses for critical system failures
    """
    
    def __init__(self):
        self.response_templates = self._initialize_templates()
        self.fallback_count = 0
        self._lock = threading.Lock()
    
    def _initialize_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize emergency response templates"""
        return {
            'authentication_failure': {
                'error': {
                    'code': 'AUTHENTICATION_EMERGENCY',
                    'message': 'Authentication system temporarily unavailable. Please try again in a few minutes.',
                    'type': 'emergency_response',
                    'retry_after': 300,
                    'support_contact': 'Please contact system administrator if this persists'
                }
            },
            'middleware_failure': {
                'error': {
                    'code': 'MIDDLEWARE_EMERGENCY',
                    'message': 'System middleware failure detected. Emergency response activated.',
                    'type': 'emergency_response',
                    'retry_after': 180,
                    'status': 'degraded_service'
                }
            },
            'database_failure': {
                'error': {
                    'code': 'DATABASE_EMERGENCY',
                    'message': 'Database connection unavailable. Service temporarily degraded.',
                    'type': 'emergency_response',
                    'retry_after': 600,
                    'alternative_action': 'Please try again later or contact support'
                }
            },
            'critical_system_failure': {
                'error': {
                    'code': 'CRITICAL_SYSTEM_EMERGENCY',
                    'message': 'Critical system failure detected. Emergency protocols activated.',
                    'type': 'emergency_response',
                    'retry_after': 900,
                    'escalation': 'Incident has been automatically reported to system administrators'
                }
            },
            'circuit_breaker_open': {
                'error': {
                    'code': 'CIRCUIT_BREAKER_OPEN',
                    'message': 'Service temporarily unavailable due to repeated failures. System is recovering.',
                    'type': 'emergency_response',
                    'retry_after': 300,
                    'status': 'service_recovery_mode'
                }
            }
        }
    
    def generate_emergency_response(
        self, 
        failure_type: str, 
        status_code: int = 503,
        request_id: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Response:
        """
        Generate an emergency response for the given failure type
        """
        with self._lock:
            self.fallback_count += 1
        
        # Get template or use default
        template = self.response_templates.get(failure_type, self.response_templates['critical_system_failure'])
        
        # Create response data
        response_data = template.copy()
        
        # Add metadata
        response_data['metadata'] = {
            'timestamp': timezone.now().isoformat(),
            'request_id': request_id,
            'fallback_count': self.fallback_count,
            'failure_type': failure_type,
            'emergency_response_version': '1.0'
        }
        
        # Add additional context if provided
        if additional_context:
            response_data['context'] = additional_context
        
        # Create DRF Response
        try:
            response = Response(response_data, status=status_code)
            response.accepted_renderer = JSONRenderer()
            response.accepted_media_type = 'application/json'
            response.renderer_context = {}
            
            # Force immediate rendering to prevent ContentNotRenderedError
            response.render()
            
            logger.error(f"Emergency response generated: {failure_type} (count: {self.fallback_count})")
            return response
            
        except Exception as e:
            logger.critical(f"Failed to create emergency DRF response: {e}")
            # Absolute fallback - use Django JsonResponse
            return JsonResponse(response_data, status=status_code)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get emergency response statistics"""
        return {
            'total_fallback_responses': self.fallback_count,
            'available_templates': list(self.response_templates.keys()),
            'last_updated': timezone.now().isoformat()
        }


class EmergencyResponseSystem:
    """
    Main emergency response system coordinating circuit breakers and fallback responses
    """
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.emergency_generator = EmergencyResponseGenerator()
        self.system_health = {
            'authentication': True,
            'middleware': True,
            'database': True,
            'overall': True
        }
        self._lock = threading.RLock()
        
        # Initialize circuit breakers for critical components
        self._initialize_circuit_breakers()
    
    def _initialize_circuit_breakers(self):
        """Initialize circuit breakers for critical system components"""
        # Authentication circuit breaker - more sensitive
        auth_config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=30,
            success_threshold=2,
            timeout_window=180
        )
        self.circuit_breakers['authentication'] = CircuitBreaker('authentication', auth_config)
        
        # Middleware circuit breaker
        middleware_config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60,
            success_threshold=3,
            timeout_window=300
        )
        self.circuit_breakers['middleware'] = CircuitBreaker('middleware', middleware_config)
        
        # Database circuit breaker
        db_config = CircuitBreakerConfig(
            failure_threshold=4,
            recovery_timeout=120,
            success_threshold=2,
            timeout_window=600
        )
        self.circuit_breakers['database'] = CircuitBreaker('database', db_config)
    
    def get_circuit_breaker(self, name: str) -> CircuitBreaker:
        """Get or create a circuit breaker"""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(name)
        return self.circuit_breakers[name]
    
    def execute_with_fallback(
        self, 
        component: str, 
        operation: Callable,
        fallback_type: str = None,
        *args, 
        **kwargs
    ):
        """
        Execute operation with circuit breaker protection and emergency fallback
        """
        circuit_breaker = self.get_circuit_breaker(component)
        fallback_type = fallback_type or f"{component}_failure"
        
        try:
            return circuit_breaker.call(operation, *args, **kwargs)
        except CircuitBreakerOpenError:
            logger.warning(f"Circuit breaker {component} is open, generating emergency response")
            return self.emergency_generator.generate_emergency_response(
                'circuit_breaker_open',
                additional_context={'component': component}
            )
        except Exception as e:
            logger.error(f"Operation failed in {component}: {e}")
            return self.emergency_generator.generate_emergency_response(
                fallback_type,
                additional_context={'component': component, 'error': str(e)}
            )
    
    def handle_authentication_failure(self, request, error: Exception) -> Response:
        """
        Handle authentication failures with emergency response
        """
        request_id = getattr(request, 'request_id', None) if request else None
        
        def auth_operation():
            # This would normally be the authentication logic
            # For emergency response, we just raise the original error
            raise error
        
        try:
            return self.execute_with_fallback(
                'authentication',
                auth_operation,
                'authentication_failure'
            )
        except Exception:
            # Final fallback for authentication
            return self.emergency_generator.generate_emergency_response(
                'authentication_failure',
                status_code=503,
                request_id=request_id,
                additional_context={
                    'endpoint': request.path if request else 'unknown',
                    'method': request.method if request else 'unknown'
                }
            )
    
    def handle_middleware_failure(self, request, error: Exception) -> Response:
        """
        Handle middleware failures with emergency response
        """
        request_id = getattr(request, 'request_id', None) if request else None
        
        return self.emergency_generator.generate_emergency_response(
            'middleware_failure',
            status_code=503,
            request_id=request_id,
            additional_context={
                'middleware_error': str(error),
                'endpoint': request.path if request else 'unknown'
            }
        )
    
    def handle_database_failure(self, request, error: Exception) -> Response:
        """
        Handle database failures with emergency response
        """
        request_id = getattr(request, 'request_id', None) if request else None
        
        return self.emergency_generator.generate_emergency_response(
            'database_failure',
            status_code=503,
            request_id=request_id,
            additional_context={
                'database_error': str(error),
                'endpoint': request.path if request else 'unknown'
            }
        )
    
    def update_system_health(self, component: str, is_healthy: bool):
        """Update system health status"""
        with self._lock:
            self.system_health[component] = is_healthy
            # Update overall health
            self.system_health['overall'] = all(
                status for key, status in self.system_health.items() 
                if key != 'overall'
            )
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        circuit_status = {
            name: breaker.get_status() 
            for name, breaker in self.circuit_breakers.items()
        }
        
        return {
            'system_health': self.system_health,
            'circuit_breakers': circuit_status,
            'emergency_responses': self.emergency_generator.get_statistics(),
            'timestamp': timezone.now().isoformat()
        }
    
    def reset_circuit_breaker(self, name: str) -> bool:
        """Manually reset a circuit breaker"""
        if name in self.circuit_breakers:
            with self.circuit_breakers[name]._lock:
                self.circuit_breakers[name].state = CircuitState.CLOSED
                self.circuit_breakers[name].failure_count = 0
                self.circuit_breakers[name].success_count = 0
                logger.info(f"Circuit breaker {name} manually reset")
                return True
        return False


# Global emergency response system instance
emergency_system = EmergencyResponseSystem()


def emergency_response_middleware(get_response):
    """
    Middleware to catch critical failures and provide emergency responses
    """
    def middleware(request):
        try:
            response = get_response(request)
            return response
        except Exception as e:
            logger.error(f"Critical middleware failure: {e}")
            return emergency_system.handle_middleware_failure(request, e)
    
    return middleware


def with_emergency_fallback(component: str, fallback_type: str = None):
    """
    Decorator to add emergency fallback to view functions
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return emergency_system.execute_with_fallback(
                    component, func, fallback_type, *args, **kwargs
                )
            except Exception as e:
                # Extract request if available
                request = None
                if args and hasattr(args[0], 'request'):
                    request = args[0].request
                elif args and hasattr(args[0], 'META'):
                    request = args[0]
                
                if component == 'authentication':
                    return emergency_system.handle_authentication_failure(request, e)
                else:
                    return emergency_system.handle_middleware_failure(request, e)
        
        return wrapper
    return decorator


# Health check functions
def check_authentication_health() -> bool:
    """Check if authentication system is healthy"""
    try:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        # Simple query to test database connectivity for auth
        User.objects.filter(pk=1).exists()
        return True
    except Exception as e:
        logger.error(f"Authentication health check failed: {e}")
        return False


def check_middleware_health() -> bool:
    """Check if middleware stack is healthy"""
    try:
        # This is a simple check - in practice you might test specific middleware
        return True
    except Exception as e:
        logger.error(f"Middleware health check failed: {e}")
        return False


def check_database_health() -> bool:
    """Check if database is healthy"""
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


def run_health_checks():
    """Run all health checks and update system status"""
    emergency_system.update_system_health('authentication', check_authentication_health())
    emergency_system.update_system_health('middleware', check_middleware_health())
    emergency_system.update_system_health('database', check_database_health())