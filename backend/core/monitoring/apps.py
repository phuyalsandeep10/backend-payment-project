"""
Django App Configuration for Core Monitoring Module

Task 2.2.2 - Core Config Decomposition
"""

from django.apps import AppConfig
import logging

logger = logging.getLogger(__name__)


class CoreMonitoringConfig(AppConfig):
    """Configuration for the core monitoring module"""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core.monitoring'
    verbose_name = 'Core Monitoring & Alerting'
    
    def ready(self):
        """Initialize monitoring module when Django starts"""
        try:
            # Initialize monitoring systems
            from . import alerting_system  # Start alerting system
            logger.info("Core monitoring module initialized successfully")
        except Exception as e:
            logger.warning(f"Core monitoring module initialization had issues: {e}")
            # Don't fail startup if there are issues during development
