"""
Django App Configuration for Services Layer

Task 2.1.1 - Service Layer Implementation
"""

from django.apps import AppConfig
import logging

logger = logging.getLogger(__name__)


class ServicesConfig(AppConfig):
    """Configuration for the services app"""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'services'
    verbose_name = 'Business Logic Services'
    
    def ready(self):
        """Initialize the service layer when Django starts"""
        try:
            from .service_registry import auto_register_services
            auto_register_services()
            logger.info("Service layer initialized successfully")
        except Exception as e:
            logger.warning(f"Service layer initialization had issues: {e}")
            # Don't fail startup if services have issues during development
