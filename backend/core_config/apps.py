from django.apps import AppConfig


class CoreConfigConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core_config'
    verbose_name = 'Core Configuration'
    
    def ready(self):
        # Import signal handlers
        try:
            from . import audit_service  # This will register the signal handlers
        except ImportError:
            pass