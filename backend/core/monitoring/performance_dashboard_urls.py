"""
Performance Dashboard URLs - Task 6.2.2

URL patterns for enhanced performance monitoring dashboard endpoints.
"""

from django.urls import path
from .performance_dashboard_views import (
    PerformanceDashboardView,
    RealTimeMetricsView,
    PerformanceAlertsAPIView,
    PerformanceThresholdsAPIView,
    PerformanceTrendsAPIView,
    PerformanceBaselineAPIView,
    PerformanceReportsAPIView
)

app_name = 'performance_dashboard'

urlpatterns = [
    # Main dashboard endpoint
    path('dashboard/', PerformanceDashboardView.as_view(), name='dashboard'),
    
    # Real-time monitoring
    path('realtime/', RealTimeMetricsView.as_view(), name='realtime_metrics'),
    
    # Alerts management
    path('alerts/', PerformanceAlertsAPIView.as_view(), name='alerts'),
    
    # Thresholds configuration
    path('thresholds/', PerformanceThresholdsAPIView.as_view(), name='thresholds'),
    
    # Trends analysis
    path('trends/', PerformanceTrendsAPIView.as_view(), name='trends'),
    
    # Baseline management
    path('baseline/', PerformanceBaselineAPIView.as_view(), name='baseline'),
    
    # Reports generation
    path('reports/', PerformanceReportsAPIView.as_view(), name='reports'),
]
