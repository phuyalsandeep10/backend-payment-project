from django.apps import AppConfig


class VerifierDashboardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Verifier_dashboard'

    def ready(self):
        pass