"""
Integration module for enhanced error logging and monitoring system
Provides configuration and setup utilities for the PRS Backend logging system
"""

import os
import logging
from typing import Dict, List, Any
from django.conf import settings
from django.core.management.commands.runserver import Command as RunServerCommand

from .structured_logger import StructuredLogger, EventType
from .error_correlation import error_tracker
from .enhanced_exception_middleware import (
    EnhancedExceptionMiddleware,
    PerformanceMonitoringMiddleware, 
    SecurityEventMiddleware
)
from .error_monitoring_dashboard import get_error_monitoring_urls


class LoggingSystemIntegrator:
    """
    Integrates the enhanced logging system with Django
    """
    
    def __init__(self):
        self.logger = StructuredLogger('logging_integrator')
    
    @staticmethod
    def get_enhanced_middleware():
        """
        Get list of enhanced middleware classes in correct order
        """
        return [
            'core.logging.structured_logger.CorrelationMiddleware',
            'core.logging.enhanced_exception_middleware.SecurityEventMiddleware',
            'core.logging.enhanced_exception_middleware.PerformanceMonitoringMiddleware',
            'core.logging.enhanced_exception_middleware.EnhancedExceptionMiddleware',
        ]
    
    @staticmethod
    def get_enhanced_logging_config():
        """
        Get enhanced logging configuration for Django settings
        """
        return {
            'version': 1,
            'disable_existing_loggers': False,
            
            'formatters': {
                'structured_json': {
                    '()': 'core.logging.formatters.StructuredJSONFormatter',
                },
                'structured_console': {
                    '()': 'core.logging.formatters.StructuredConsoleFormatter',
                },
                'verbose': {
                    'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
                    'style': '{',
                },
            },
            
            'filters': {
                'correlation_filter': {
                    '()': 'core.logging.filters.CorrelationFilter',
                },
                'security_filter': {
                    '()': 'core.logging.filters.SecurityFilter',
                },
                'performance_filter': {
                    '()': 'core.logging.filters.PerformanceFilter',
                },
            },
            
            'handlers': {
                'console': {
                    'level': 'INFO',
                    'class': 'logging.StreamHandler',
                    'formatter': 'structured_console',
                    'filters': ['correlation_filter'],
                },
                
                'application_file': {
                    'level': 'INFO',
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': os.path.join(settings.BASE_DIR, 'logs', 'application.log'),
                    'maxBytes': 20971520,  # 20MB
                    'backupCount': 10,
                    'formatter': 'structured_json',
                    'filters': ['correlation_filter'],
                },
                
                'error_file': {
                    'level': 'ERROR',
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': os.path.join(settings.BASE_DIR, 'logs', 'errors.log'),
                    'maxBytes': 20971520,  # 20MB
                    'backupCount': 20,
                    'formatter': 'structured_json',
                    'filters': ['correlation_filter'],
                },
                
                'security_file': {
                    'level': 'WARNING',
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': os.path.join(settings.BASE_DIR, 'logs', 'security.log'),
                    'maxBytes': 20971520,  # 20MB
                    'backupCount': 20,
                    'formatter': 'structured_json',
                    'filters': ['security_filter'],
                },
                
                'performance_file': {
                    'level': 'WARNING',
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': os.path.join(settings.BASE_DIR, 'logs', 'performance.log'),
                    'maxBytes': 20971520,  # 20MB
                    'backupCount': 10,
                    'formatter': 'structured_json',
                    'filters': ['performance_filter'],
                },
                
                'correlation_file': {
                    'level': 'INFO',
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': os.path.join(settings.BASE_DIR, 'logs', 'correlation.log'),
                    'maxBytes': 20971520,  # 20MB
                    'backupCount': 15,
                    'formatter': 'structured_json',
                    'filters': ['correlation_filter'],
                },
            },
            
            'loggers': {
                'django': {
                    'handlers': ['console', 'application_file', 'error_file'],
                    'level': 'INFO',
                    'propagate': False,
                },
                
                'django.request': {
                    'handlers': ['error_file', 'correlation_file'],
                    'level': 'ERROR',
                    'propagate': False,
                },
                
                'django.security': {
                    'handlers': ['security_file'],
                    'level': 'INFO',
                    'propagate': False,
                },
                
                'prs.application': {
                    'handlers': ['console', 'application_file', 'correlation_file'],
                    'level': 'INFO',
                    'propagate': False,
                },
                
                'exception_middleware': {
                    'handlers': ['error_file', 'correlation_file'],
                    'level': 'INFO',
                    'propagate': False,
                },
                
                'performance_monitoring': {
                    'handlers': ['performance_file', 'correlation_file'],
                    'level': 'WARNING',
                    'propagate': False,
                },
                
                'security_monitoring': {
                    'handlers': ['security_file', 'correlation_file'],
                    'level': 'WARNING',
                    'propagate': False,
                },
                
                'error_correlation': {
                    'handlers': ['correlation_file'],
                    'level': 'INFO',
                    'propagate': False,
                },
                
                'error_dashboard': {
                    'handlers': ['application_file'],
                    'level': 'INFO',
                    'propagate': False,
                },
                
                'root': {
                    'handlers': ['console'],
                    'level': 'WARNING',
                },
            },
        }
    
    @staticmethod
    def get_enhanced_settings():
        """
        Get additional Django settings for enhanced logging
        """
        return {
            # Error correlation settings
            'ERROR_CORRELATION_ENABLED': True,
            'ERROR_CORRELATION_REDIS_URL': getattr(settings, 'REDIS_URL', None),
            
            # Performance monitoring settings
            'PERFORMANCE_MONITORING_ENABLED': True,
            'SLOW_REQUEST_THRESHOLD_MS': 1000,
            'VERY_SLOW_REQUEST_THRESHOLD_MS': 5000,
            
            # Security monitoring settings
            'SECURITY_MONITORING_ENABLED': True,
            'LOG_SUSPICIOUS_REQUESTS': True,
            
            # Error dashboard settings
            'ERROR_DASHBOARD_ENABLED': True,
            'ERROR_DASHBOARD_RETENTION_DAYS': 30,
            
            # Structured logging settings
            'STRUCTURED_LOGGING_ENABLED': True,
            'LOG_CORRELATION_ENABLED': True,
            'LOG_USER_CONTEXT': True,
            'LOG_REQUEST_CONTEXT': True,
            
            # Service identification
            'SERVICE_NAME': 'prs-backend',
            'SERVICE_VERSION': getattr(settings, 'VERSION', '1.0.0'),
            'ENVIRONMENT': getattr(settings, 'ENVIRONMENT', 'development'),
        }
    
    def setup_logging_directories(self):
        """
        Create necessary logging directories
        """
        logs_dir = os.path.join(settings.BASE_DIR, 'logs')
        
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)
            self.logger.info(
                EventType.SYSTEM_ERROR,
                f"Created logs directory: {logs_dir}",
                tags=['setup', 'logging']
            )
        
        # Create subdirectories for different log types
        subdirs = ['archived', 'temp', 'correlation']
        for subdir in subdirs:
            path = os.path.join(logs_dir, subdir)
            if not os.path.exists(path):
                os.makedirs(path)
    
    def validate_configuration(self):
        """
        Validate the logging configuration
        """
        errors = []
        warnings = []
        
        # Check Redis connection for error correlation
        if hasattr(settings, 'REDIS_URL'):
            try:
                import redis
                client = redis.Redis.from_url(settings.REDIS_URL)
                client.ping()
            except Exception as e:
                warnings.append(f"Redis connection failed: {e}")
        else:
            warnings.append("REDIS_URL not configured - error correlation will use memory only")
        
        # Check log directory permissions
        logs_dir = os.path.join(settings.BASE_DIR, 'logs')
        if not os.access(logs_dir, os.W_OK):
            errors.append(f"Logs directory is not writable: {logs_dir}")
        
        # Check required settings
        required_settings = [
            'SECRET_KEY',
            'DEBUG',
            'ALLOWED_HOSTS',
        ]
        
        for setting_name in required_settings:
            if not hasattr(settings, setting_name):
                errors.append(f"Required setting missing: {setting_name}")
        
        # Report validation results
        if errors:
            self.logger.error(
                EventType.SYSTEM_ERROR,
                "Logging configuration validation failed",
                extra_data={'errors': errors, 'warnings': warnings},
                tags=['validation', 'configuration', 'error']
            )
            return False
        
        if warnings:
            self.logger.warning(
                EventType.SYSTEM_ERROR,
                "Logging configuration validation warnings",
                extra_data={'warnings': warnings},
                tags=['validation', 'configuration', 'warning']
            )
        
        self.logger.info(
            EventType.SYSTEM_ERROR,
            "Logging configuration validated successfully",
            tags=['validation', 'configuration', 'success']
        )
        
        return True
    
    def initialize_system(self):
        """
        Initialize the enhanced logging system
        """
        self.setup_logging_directories()
        
        if not self.validate_configuration():
            raise RuntimeError("Logging system validation failed")
        
        # Initialize error tracker
        self.logger.info(
            EventType.SYSTEM_ERROR,
            "Error correlation system initialized",
            extra_data={
                'tracker_active': True,
                'redis_available': error_tracker.redis_client is not None
            },
            tags=['initialization', 'error_correlation']
        )
        
        # Start cleanup tasks
        self._setup_cleanup_tasks()
        
        self.logger.info(
            EventType.SYSTEM_ERROR,
            "Enhanced logging system initialized successfully",
            extra_data={
                'structured_logging': True,
                'error_correlation': True,
                'performance_monitoring': True,
                'security_monitoring': True,
                'error_dashboard': True
            },
            tags=['initialization', 'logging_system', 'success']
        )
    
    def _setup_cleanup_tasks(self):
        """
        Setup periodic cleanup tasks
        """
        try:
            from django_celery_beat.models import PeriodicTask, IntervalSchedule
            
            # Create cleanup schedule (daily)
            schedule, created = IntervalSchedule.objects.get_or_create(
                every=24,
                period=IntervalSchedule.HOURS,
            )
            
            # Create cleanup task
            PeriodicTask.objects.get_or_create(
                name='Clean up old error clusters',
                defaults={
                    'task': 'core.logging.tasks.cleanup_old_errors',
                    'interval': schedule,
                    'args': '[30]'  # 30 days retention
                }
            )
            
        except ImportError:
            # Celery not available, skip periodic tasks
            self.logger.warning(
                EventType.SYSTEM_ERROR,
                "Celery not available - cleanup tasks not scheduled",
                tags=['cleanup', 'celery', 'warning']
            )
        except Exception as e:
            self.logger.warning(
                EventType.SYSTEM_ERROR,
                "Failed to setup cleanup tasks",
                exception=e,
                tags=['cleanup', 'setup', 'warning']
            )


def integrate_with_settings(settings_module):
    """
    Integrate enhanced logging with Django settings
    """
    integrator = LoggingSystemIntegrator()
    
    # Add enhanced middleware
    enhanced_middleware = integrator.get_enhanced_middleware()
    
    if hasattr(settings_module, 'MIDDLEWARE'):
        settings_module.MIDDLEWARE = enhanced_middleware + list(settings_module.MIDDLEWARE)
    
    # Update logging configuration
    settings_module.LOGGING = integrator.get_enhanced_logging_config()
    
    # Add enhanced settings
    enhanced_settings = integrator.get_enhanced_settings()
    for key, value in enhanced_settings.items():
        if not hasattr(settings_module, key):
            setattr(settings_module, key, value)
    
    return integrator


def get_admin_urls():
    """
    Get URLs for admin integration
    """
    from django.urls import path, include
    
    return [
        path('admin/', include(get_error_monitoring_urls())),
    ]


def setup_development_logging():
    """
    Setup logging for development environment
    """
    integrator = LoggingSystemIntegrator()
    integrator.initialize_system()
    
    # Override some settings for development
    logging.getLogger('prs.application').setLevel(logging.DEBUG)
    logging.getLogger('exception_middleware').setLevel(logging.DEBUG)
    
    return integrator


def setup_production_logging():
    """
    Setup logging for production environment
    """
    integrator = LoggingSystemIntegrator()
    integrator.initialize_system()
    
    # Production-specific configurations
    # Reduce log verbosity
    logging.getLogger('django.db.backends').setLevel(logging.WARNING)
    
    # Enable all monitoring
    os.environ.setdefault('PERFORMANCE_MONITORING_ENABLED', 'True')
    os.environ.setdefault('SECURITY_MONITORING_ENABLED', 'True')
    os.environ.setdefault('ERROR_CORRELATION_ENABLED', 'True')
    
    return integrator


# Convenience functions for common operations
def log_business_event(event_name: str, **context):
    """
    Log a business event with structured logging
    """
    logger = StructuredLogger('business_events')
    logger.log_business_event(event_name, **context)


def log_security_event(description: str, severity: str = 'medium', **context):
    """
    Log a security event
    """
    logger = StructuredLogger('security_events')
    logger.log_security_event(description, severity, **context)


def log_performance_issue(operation: str, duration_ms: float, threshold_ms: float = 1000, **context):
    """
    Log a performance issue
    """
    logger = StructuredLogger('performance_events')
    logger.log_performance_issue(operation, duration_ms, threshold_ms, **context)


def track_user_action(user, action: str, **context):
    """
    Track a user action with context
    """
    logger = StructuredLogger('user_actions')
    logger.log_user_action(
        action=action,
        user_id=user.id if user else None,
        **context
    )
