"""
Django App Configuration for Core Performance Module

Task 2.2.3 - Core Config Decomposition
"""

from django.apps import AppConfig
import logging

logger = logging.getLogger(__name__)


class CorePerformanceConfig(AppConfig):
    """Configuration for the core performance module"""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core.performance'
    verbose_name = 'Core Performance & Optimization'
    
    def ready(self):
        """Initialize performance module when Django starts"""
        try:
            # Initialize performance monitoring and caching
            from . import strategic_cache_manager  # Initialize cache manager
            logger.info("Core performance module initialized successfully")
        except Exception as e:
            logger.warning(f"Core performance module initialization had issues: {e}")
            # Don't fail startup if there are issues during development
