"""
Monitoring URLs
URL configuration for performance monitoring endpoints
"""

from django.urls import path
from . import monitoring_views

app_name = 'monitoring'

urlpatterns = [
    # Performance monitoring endpoints
    path('performance/summary/', monitoring_views.PerformanceSummaryView.as_view(), name='performance_summary'),
    path('performance/trends/', monitoring_views.PerformanceTrendsView.as_view(), name='performance_trends'),
    path('performance/alerts/', monitoring_views.PerformanceAlertsView.as_view(), name='performance_alerts'),
    
    # Database monitoring
    path('database/metrics/', monitoring_views.DatabaseMetricsView.as_view(), name='database_metrics'),
    path('database/slow-queries/', monitoring_views.SlowQueriesView.as_view(), name='slow_queries'),
    
    # API monitoring
    path('api/metrics/', monitoring_views.APIMetricsView.as_view(), name='api_metrics'),
    path('api/slow-calls/', monitoring_views.SlowAPICallsView.as_view(), name='slow_api_calls'),
    
    # System monitoring
    path('system/metrics/', monitoring_views.SystemMetricsView.as_view(), name='system_metrics'),
    path('system/health/', monitoring_views.health_check, name='health_check'),
    
    # Admin configuration endpoints
    path('config/', monitoring_views.PerformanceConfigView.as_view(), name='performance_config'),
    path('maintenance/', monitoring_views.PerformanceMaintenanceView.as_view(), name='performance_maintenance'),
]