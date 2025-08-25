"""
URL Configuration for Core Monitoring Module

Task 2.2.2 - Core Config Decomposition
"""

from django.urls import path, include

app_name = 'monitoring'

urlpatterns = [
    # System monitoring and health checks
    path('system/', include('core.monitoring.monitoring_urls')),
    
    # Alerting system
    path('alerts/', include('core.monitoring.alerting_urls')),
    
    # Response monitoring
    path('responses/', include('core.monitoring.response_monitoring_urls')),
    
    # Enhanced performance dashboard - Task 6.2.2
    path('performance/', include('core.monitoring.performance_dashboard_urls')),
]
