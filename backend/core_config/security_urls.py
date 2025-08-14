"""
Security Dashboard URL Configuration
"""

from django.urls import path, include
from .security_dashboard_views import (
    SecurityDashboardView,
    SecurityEventsView,
    SecurityAlertsView,
    AuditTrailView,
    UserActivityView,
    ComplianceReportsView,
    SecurityMetricsView,
    log_user_action,
    security_summary
)

app_name = 'security'

urlpatterns = [
    # Main dashboard
    path('dashboard/', SecurityDashboardView.as_view(), name='dashboard'),
    path('summary/', security_summary, name='summary'),
    path('metrics/', SecurityMetricsView.as_view(), name='metrics'),
    
    # Security events
    path('events/', SecurityEventsView.as_view(), name='events'),
    
    # Security alerts
    path('alerts/', SecurityAlertsView.as_view(), name='alerts'),
    path('alerts/<uuid:alert_id>/', SecurityAlertsView.as_view(), name='alert_detail'),
    
    # Audit trail
    path('audit/', AuditTrailView.as_view(), name='audit_trail'),
    path('audit/user/<int:user_id>/', UserActivityView.as_view(), name='user_activity'),
    path('audit/my-activity/', UserActivityView.as_view(), name='my_activity'),
    
    # Compliance reports
    path('reports/', ComplianceReportsView.as_view(), name='compliance_reports'),
    
    # User actions
    path('log-action/', log_user_action, name='log_user_action'),
]