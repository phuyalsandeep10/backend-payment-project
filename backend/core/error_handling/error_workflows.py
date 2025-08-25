"""
Advanced Error Handling Workflows for PRS Backend
Implements circuit breakers, retry policies, and graceful degradation patterns
"""

import time
import asyncio
import threading
from typing import Dict, Any, Optional, Callable, List, Union, Type, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from contextlib import contextmanager
from collections import defaultdict, deque
from functools import wraps
import json

from django.core.cache import cache
from django.conf import settings
from django.utils import timezone

from ..logging import StructuredLogger, EventType, log_business_event, track_error


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"         # Blocking calls
    HALF_OPEN = "half_open"  # Testing recovery


class RetryPolicy(Enum):
    """Retry policy types"""
    NO_RETRY = "no_retry"
    IMMEDIATE = "immediate"
    FIXED_DELAY = "fixed_delay"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout: int = 60  # seconds
    success_threshold: int = 3  # for half-open state
    timeout: int = 30  # operation timeout
    excluded_exceptions: List[Type[Exception]] = field(default_factory=list)


@dataclass
class RetryConfig:
    """Retry configuration"""
    policy: RetryPolicy = RetryPolicy.EXPONENTIAL_BACKOFF
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    multiplier: float = 2.0
    jitter: bool = True
    retryable_exceptions: List[Type[Exception]] = field(default_factory=list)


@dataclass
class DegradationConfig:
    """Graceful degradation configuration"""
    enabled: bool = True
    fallback_function: Optional[Callable] = None
    degraded_response: Optional[Any] = None
    cache_fallback: bool = True
    cache_ttl: int = 300  # seconds


class CircuitBreaker:
    """
    Circuit breaker implementation for fault tolerance
    """
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.logger = StructuredLogger(f'circuit_breaker.{name}')
        self._lock = threading.RLock()
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        with self._lock:
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                    self.logger.info(
                        EventType.SYSTEM_ERROR,
                        f"Circuit breaker {self.name} transitioning to HALF_OPEN",
                        tags=['circuit_breaker', 'state_transition']
                    )
                else:
                    raise CircuitBreakerOpenException(f"Circuit breaker {self.name} is OPEN")
            
            start_time = time.time()
            
            try:
                # Execute with timeout
                result = self._execute_with_timeout(func, *args, **kwargs)
                
                # Record success
                self._record_success()
                
                duration = (time.time() - start_time) * 1000
                self.logger.debug(
                    EventType.SYSTEM_ERROR,
                    f"Circuit breaker {self.name} call succeeded",
                    extra_data={'duration_ms': duration, 'state': self.state.value},
                    tags=['circuit_breaker', 'success']
                )
                
                return result
                
            except Exception as e:
                # Check if exception should be ignored
                if type(e) in self.config.excluded_exceptions:
                    raise e
                
                # Record failure
                self._record_failure(e)
                
                duration = (time.time() - start_time) * 1000
                self.logger.error(
                    EventType.SYSTEM_ERROR,
                    f"Circuit breaker {self.name} call failed",
                    exception=e,
                    extra_data={
                        'duration_ms': duration,
                        'state': self.state.value,
                        'failure_count': self.failure_count
                    },
                    tags=['circuit_breaker', 'failure']
                )
                
                raise e
    
    def _execute_with_timeout(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with timeout"""
        if self.config.timeout <= 0:
            return func(*args, **kwargs)
        
        # Simple timeout implementation
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Operation timed out after {self.config.timeout} seconds")
        
        # Set timeout alarm
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.config.timeout)
        
        try:
            result = func(*args, **kwargs)
            signal.alarm(0)  # Cancel alarm
            return result
        finally:
            signal.signal(signal.SIGALRM, old_handler)
    
    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset the circuit"""
        if self.last_failure_time is None:
            return False
        
        return (time.time() - self.last_failure_time) >= self.config.recovery_timeout
    
    def _record_success(self):
        """Record a successful call"""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.logger.info(
                    EventType.SYSTEM_ERROR,
                    f"Circuit breaker {self.name} reset to CLOSED",
                    extra_data={'success_count': self.success_count},
                    tags=['circuit_breaker', 'recovered']
                )
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0
    
    def _record_failure(self, exception: Exception):
        """Record a failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self.logger.warning(
                EventType.SYSTEM_ERROR,
                f"Circuit breaker {self.name} reopened",
                exception=exception,
                tags=['circuit_breaker', 'reopened']
            )
        elif self.state == CircuitState.CLOSED and self.failure_count >= self.config.failure_threshold:
            self.state = CircuitState.OPEN
            self.logger.critical(
                EventType.SYSTEM_ERROR,
                f"Circuit breaker {self.name} opened",
                exception=exception,
                extra_data={'failure_count': self.failure_count},
                tags=['circuit_breaker', 'opened']
            )
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state"""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure_time': self.last_failure_time,
            'config': {
                'failure_threshold': self.config.failure_threshold,
                'recovery_timeout': self.config.recovery_timeout,
                'success_threshold': self.config.success_threshold,
            }
        }


class RetryMechanism:
    """
    Advanced retry mechanism with various backoff strategies
    """
    
    def __init__(self, name: str, config: RetryConfig):
        self.name = name
        self.config = config
        self.logger = StructuredLogger(f'retry_mechanism.{name}')
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic"""
        if self.config.policy == RetryPolicy.NO_RETRY:
            return func(*args, **kwargs)
        
        last_exception = None
        
        for attempt in range(self.config.max_attempts):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                
                # Log successful execution
                if attempt > 0:
                    duration = (time.time() - start_time) * 1000
                    self.logger.info(
                        EventType.SYSTEM_ERROR,
                        f"Retry {self.name} succeeded on attempt {attempt + 1}",
                        extra_data={
                            'attempt': attempt + 1,
                            'total_attempts': self.config.max_attempts,
                            'duration_ms': duration
                        },
                        tags=['retry', 'success']
                    )
                
                return result
                
            except Exception as e:
                last_exception = e
                
                # Check if exception is retryable
                if not self._is_retryable_exception(e):
                    self.logger.warning(
                        EventType.SYSTEM_ERROR,
                        f"Retry {self.name} stopped - non-retryable exception",
                        exception=e,
                        extra_data={'attempt': attempt + 1},
                        tags=['retry', 'non_retryable']
                    )
                    raise e
                
                # Last attempt failed
                if attempt == self.config.max_attempts - 1:
                    self.logger.error(
                        EventType.SYSTEM_ERROR,
                        f"Retry {self.name} exhausted all attempts",
                        exception=e,
                        extra_data={'total_attempts': self.config.max_attempts},
                        tags=['retry', 'exhausted']
                    )
                    raise e
                
                # Calculate delay and wait
                delay = self._calculate_delay(attempt)
                
                self.logger.warning(
                    EventType.SYSTEM_ERROR,
                    f"Retry {self.name} attempt {attempt + 1} failed, retrying in {delay:.2f}s",
                    exception=e,
                    extra_data={
                        'attempt': attempt + 1,
                        'next_delay': delay,
                        'remaining_attempts': self.config.max_attempts - attempt - 1
                    },
                    tags=['retry', 'failed_attempt']
                )
                
                time.sleep(delay)
        
        # Should never reach here, but just in case
        raise last_exception
    
    def _is_retryable_exception(self, exception: Exception) -> bool:
        """Check if exception is retryable"""
        if not self.config.retryable_exceptions:
            # Default retryable exceptions
            retryable_types = [
                ConnectionError,
                TimeoutError,
                OSError,
            ]
        else:
            retryable_types = self.config.retryable_exceptions
        
        return any(isinstance(exception, exc_type) for exc_type in retryable_types)
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for next retry attempt"""
        if self.config.policy == RetryPolicy.IMMEDIATE:
            delay = 0
        elif self.config.policy == RetryPolicy.FIXED_DELAY:
            delay = self.config.base_delay
        elif self.config.policy == RetryPolicy.LINEAR_BACKOFF:
            delay = self.config.base_delay * (attempt + 1)
        elif self.config.policy == RetryPolicy.EXPONENTIAL_BACKOFF:
            delay = self.config.base_delay * (self.config.multiplier ** attempt)
        else:
            delay = self.config.base_delay
        
        # Apply maximum delay limit
        delay = min(delay, self.config.max_delay)
        
        # Apply jitter to avoid thundering herd
        if self.config.jitter:
            import random
            delay = delay * (0.5 + random.random() * 0.5)
        
        return delay


class GracefulDegradation:
    """
    Graceful degradation mechanism for fault tolerance
    """
    
    def __init__(self, name: str, config: DegradationConfig):
        self.name = name
        self.config = config
        self.logger = StructuredLogger(f'degradation.{name}')
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with graceful degradation"""
        try:
            return func(*args, **kwargs)
            
        except Exception as e:
            if not self.config.enabled:
                raise e
            
            self.logger.warning(
                EventType.SYSTEM_ERROR,
                f"Graceful degradation {self.name} activated",
                exception=e,
                tags=['degradation', 'activated']
            )
            
            # Try fallback function first
            if self.config.fallback_function:
                try:
                    result = self.config.fallback_function(*args, **kwargs)
                    self.logger.info(
                        EventType.SYSTEM_ERROR,
                        f"Graceful degradation {self.name} used fallback function",
                        tags=['degradation', 'fallback_success']
                    )
                    return result
                except Exception as fallback_error:
                    self.logger.error(
                        EventType.SYSTEM_ERROR,
                        f"Graceful degradation {self.name} fallback failed",
                        exception=fallback_error,
                        tags=['degradation', 'fallback_failed']
                    )
            
            # Try cached response
            if self.config.cache_fallback:
                cached_result = self._get_cached_response(func, args, kwargs)
                if cached_result is not None:
                    self.logger.info(
                        EventType.SYSTEM_ERROR,
                        f"Graceful degradation {self.name} used cached response",
                        tags=['degradation', 'cache_success']
                    )
                    return cached_result
            
            # Return degraded response
            if self.config.degraded_response is not None:
                self.logger.info(
                    EventType.SYSTEM_ERROR,
                    f"Graceful degradation {self.name} returned degraded response",
                    tags=['degradation', 'degraded_response']
                )
                return self.config.degraded_response
            
            # No degradation options available
            self.logger.error(
                EventType.SYSTEM_ERROR,
                f"Graceful degradation {self.name} - no fallback available",
                exception=e,
                tags=['degradation', 'no_fallback']
            )
            raise e
    
    def _get_cached_response(self, func: Callable, args: tuple, kwargs: dict) -> Any:
        """Try to get cached response"""
        try:
            # Create cache key from function and arguments
            cache_key = self._create_cache_key(func, args, kwargs)
            return cache.get(cache_key)
        except Exception:
            return None
    
    def _create_cache_key(self, func: Callable, args: tuple, kwargs: dict) -> str:
        """Create cache key for function call"""
        import hashlib
        
        key_data = {
            'function': f"{func.__module__}.{func.__name__}",
            'args': str(args),
            'kwargs': str(sorted(kwargs.items()))
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        key_hash = hashlib.md5(key_string.encode()).hexdigest()
        
        return f"degradation:{self.name}:{key_hash}"


class ErrorWorkflowManager:
    """
    Manages error handling workflows with circuit breakers, retries, and degradation
    """
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.retry_mechanisms: Dict[str, RetryMechanism] = {}
        self.degradation_handlers: Dict[str, GracefulDegradation] = {}
        self.logger = StructuredLogger('error_workflow_manager')
        self._lock = threading.RLock()
    
    def register_circuit_breaker(self, name: str, config: CircuitBreakerConfig) -> CircuitBreaker:
        """Register a circuit breaker"""
        with self._lock:
            circuit_breaker = CircuitBreaker(name, config)
            self.circuit_breakers[name] = circuit_breaker
            
            self.logger.info(
                EventType.SYSTEM_ERROR,
                f"Circuit breaker registered: {name}",
                extra_data=config.__dict__,
                tags=['circuit_breaker', 'registered']
            )
            
            return circuit_breaker
    
    def register_retry_mechanism(self, name: str, config: RetryConfig) -> RetryMechanism:
        """Register a retry mechanism"""
        with self._lock:
            retry_mechanism = RetryMechanism(name, config)
            self.retry_mechanisms[name] = retry_mechanism
            
            self.logger.info(
                EventType.SYSTEM_ERROR,
                f"Retry mechanism registered: {name}",
                extra_data={'policy': config.policy.value, 'max_attempts': config.max_attempts},
                tags=['retry', 'registered']
            )
            
            return retry_mechanism
    
    def register_degradation_handler(self, name: str, config: DegradationConfig) -> GracefulDegradation:
        """Register a graceful degradation handler"""
        with self._lock:
            degradation_handler = GracefulDegradation(name, config)
            self.degradation_handlers[name] = degradation_handler
            
            self.logger.info(
                EventType.SYSTEM_ERROR,
                f"Degradation handler registered: {name}",
                extra_data={'enabled': config.enabled, 'has_fallback': config.fallback_function is not None},
                tags=['degradation', 'registered']
            )
            
            return degradation_handler
    
    def execute_with_protection(self, workflow_name: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with full error handling protection"""
        
        # Get workflow components
        circuit_breaker = self.circuit_breakers.get(workflow_name)
        retry_mechanism = self.retry_mechanisms.get(workflow_name)
        degradation_handler = self.degradation_handlers.get(workflow_name)
        
        # Define the execution chain
        def execute_with_retry():
            if retry_mechanism:
                return retry_mechanism.execute(func, *args, **kwargs)
            else:
                return func(*args, **kwargs)
        
        def execute_with_circuit_breaker():
            if circuit_breaker:
                return circuit_breaker.call(execute_with_retry)
            else:
                return execute_with_retry()
        
        def execute_with_degradation():
            if degradation_handler:
                return degradation_handler.execute(execute_with_circuit_breaker)
            else:
                return execute_with_circuit_breaker()
        
        # Execute with full protection
        start_time = time.time()
        
        try:
            result = execute_with_degradation()
            
            # Log successful execution
            duration = (time.time() - start_time) * 1000
            self.logger.debug(
                EventType.SYSTEM_ERROR,
                f"Protected execution succeeded: {workflow_name}",
                extra_data={'duration_ms': duration},
                tags=['workflow', 'success']
            )
            
            return result
            
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            
            self.logger.error(
                EventType.SYSTEM_ERROR,
                f"Protected execution failed: {workflow_name}",
                exception=e,
                extra_data={'duration_ms': duration},
                tags=['workflow', 'failed']
            )
            
            raise e
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all error handling components"""
        return {
            'circuit_breakers': {
                name: cb.get_state() for name, cb in self.circuit_breakers.items()
            },
            'retry_mechanisms': {
                name: {
                    'name': rm.name,
                    'policy': rm.config.policy.value,
                    'max_attempts': rm.config.max_attempts
                } for name, rm in self.retry_mechanisms.items()
            },
            'degradation_handlers': {
                name: {
                    'name': dh.name,
                    'enabled': dh.config.enabled,
                    'has_fallback': dh.config.fallback_function is not None
                } for name, dh in self.degradation_handlers.items()
            }
        }


# Global workflow manager
workflow_manager = ErrorWorkflowManager()


# Decorator for protected functions
def protected(workflow_name: str, 
              circuit_breaker_config: CircuitBreakerConfig = None,
              retry_config: RetryConfig = None,
              degradation_config: DegradationConfig = None):
    """
    Decorator to apply error handling protection to functions
    
    Usage:
        @protected('user_service', 
                   circuit_breaker_config=CircuitBreakerConfig(failure_threshold=3),
                   retry_config=RetryConfig(max_attempts=3))
        def get_user(user_id):
            # Function implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        # Register components if configurations provided
        if circuit_breaker_config:
            workflow_manager.register_circuit_breaker(workflow_name, circuit_breaker_config)
        
        if retry_config:
            workflow_manager.register_retry_mechanism(workflow_name, retry_config)
        
        if degradation_config:
            workflow_manager.register_degradation_handler(workflow_name, degradation_config)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            return workflow_manager.execute_with_protection(workflow_name, func, *args, **kwargs)
        
        return wrapper
    
    return decorator


# Custom exceptions
class CircuitBreakerOpenException(Exception):
    """Exception raised when circuit breaker is open"""
    pass


class RetryExhaustedException(Exception):
    """Exception raised when all retry attempts are exhausted"""
    pass


# Convenience functions
def create_database_protection() -> str:
    """Create standard database operation protection"""
    workflow_name = 'database_operations'
    
    workflow_manager.register_circuit_breaker(
        workflow_name,
        CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60,
            timeout=30
        )
    )
    
    workflow_manager.register_retry_mechanism(
        workflow_name,
        RetryConfig(
            policy=RetryPolicy.EXPONENTIAL_BACKOFF,
            max_attempts=3,
            base_delay=1.0,
            retryable_exceptions=[OperationalError, ConnectionError]
        )
    )
    
    return workflow_name


def create_api_protection() -> str:
    """Create standard API operation protection"""
    workflow_name = 'api_operations'
    
    workflow_manager.register_circuit_breaker(
        workflow_name,
        CircuitBreakerConfig(
            failure_threshold=10,
            recovery_timeout=30,
            timeout=15
        )
    )
    
    workflow_manager.register_retry_mechanism(
        workflow_name,
        RetryConfig(
            policy=RetryPolicy.EXPONENTIAL_BACKOFF,
            max_attempts=2,
            base_delay=0.5,
            max_delay=5.0
        )
    )
    
    return workflow_name


def create_external_service_protection(fallback_function: Callable = None) -> str:
    """Create protection for external service calls"""
    workflow_name = 'external_services'
    
    workflow_manager.register_circuit_breaker(
        workflow_name,
        CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=60,
            timeout=20
        )
    )
    
    workflow_manager.register_retry_mechanism(
        workflow_name,
        RetryConfig(
            policy=RetryPolicy.EXPONENTIAL_BACKOFF,
            max_attempts=3,
            base_delay=2.0,
            retryable_exceptions=[ConnectionError, TimeoutError]
        )
    )
    
    workflow_manager.register_degradation_handler(
        workflow_name,
        DegradationConfig(
            enabled=True,
            fallback_function=fallback_function,
            cache_fallback=True,
            cache_ttl=300
        )
    )
    
    return workflow_name
