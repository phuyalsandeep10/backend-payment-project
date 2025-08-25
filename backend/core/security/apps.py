"""
Django App Configuration for Core Security Module

Task 2.2.1 - Core Config Decomposition
"""

from django.apps import AppConfig
import logging

logger = logging.getLogger(__name__)


class CoreSecurityConfig(AppConfig):
    """Configuration for the core security module"""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core.security'
    verbose_name = 'Core Security'
    
    def ready(self):
        """Initialize security module when Django starts"""
        try:
            # Import signal handlers and middleware registration
            from . import security_monitoring  # Register security event signals
            logger.info("Core security module initialized successfully")
        except Exception as e:
            logger.warning(f"Core security module initialization had issues: {e}")
            # Don't fail startup if there are issues during development
