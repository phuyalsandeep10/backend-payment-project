from django.apps import AppConfig


class SalesDashboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "Sales_dashboard"

    def ready(self):
        import Sales_dashboard.signals
