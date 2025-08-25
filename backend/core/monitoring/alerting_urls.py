"""
Alerting URLs
URL configuration for alerting system endpoints
"""

from django.urls import path
from . import alerting_views

app_name = 'alerting'

urlpatterns = [
    # Alert history and summary
    path('history/', alerting_views.AlertHistoryView.as_view(), name='alert_history'),
    path('summary/', alerting_views.AlertSummaryView.as_view(), name='alert_summary'),
    path('status/', alerting_views.AlertStatusView.as_view(), name='alert_status'),
    
    # Alert rules management (admin only)
    path('rules/', alerting_views.AlertRulesView.as_view(), name='alert_rules'),
    path('rules/test/', alerting_views.AlertRuleTestView.as_view(), name='test_alert_rule'),
    
    # Configuration (admin only)
    path('config/', alerting_views.AlertConfigView.as_view(), name='alert_config'),
    
    # Webhook for external alerts
    path('webhook/', alerting_views.alert_webhook, name='alert_webhook'),
]