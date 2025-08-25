from django.apps import AppConfig


class SalesDashboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.Sales_dashboard"

    def ready(self):
        import apps.Sales_dashboard.signals
