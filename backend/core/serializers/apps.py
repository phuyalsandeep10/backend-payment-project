"""
Django App Configuration for Core Serializers

Task 2.4.2 - Reusable Serializer Components
"""

from django.apps import AppConfig


class CoreSerializersConfig(AppConfig):
    """Configuration for the core serializers library"""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core.serializers'
    verbose_name = 'Core Serializer Library'
    
    def ready(self):
        """Initialize the serializer library when Django starts"""
        # The serializer library doesn't need special initialization
        # All components are available for import when needed
        pass
