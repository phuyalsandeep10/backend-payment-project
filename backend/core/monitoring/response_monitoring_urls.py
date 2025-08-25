"""
Response Processing Monitoring URLs
URL patterns for response processing monitoring endpoints
"""

from django.urls import path
from . import response_monitoring_views

app_name = 'response_monitoring'

urlpatterns = [
    # Response type metrics
    path('response-types/', 
         response_monitoring_views.ResponseTypeMetricsView.as_view(), 
         name='response_types'),
    
    # Template rendering metrics
    path('template-rendering/', 
         response_monitoring_views.TemplateRenderMetricsView.as_view(), 
         name='template_rendering'),
    
    # Error metrics
    path('errors/', 
         response_monitoring_views.ResponseErrorMetricsView.as_view(), 
         name='errors'),
    
    # ContentNotRenderedError specific tracking
    path('content-not-rendered-errors/', 
         response_monitoring_views.ContentNotRenderedErrorsView.as_view(), 
         name='content_not_rendered_errors'),
    
    # Slow render metrics
    path('slow-renders/', 
         response_monitoring_views.SlowRenderMetricsView.as_view(), 
         name='slow_renders'),
    
    # Comprehensive overview
    path('overview/', 
         response_monitoring_views.ResponseProcessingOverviewView.as_view(), 
         name='overview'),
    
    # Health status
    path('health/', 
         response_monitoring_views.ResponseProcessingHealthView.as_view(), 
         name='health'),
    
    # Configuration (admin only)
    path('config/', 
         response_monitoring_views.ResponseMonitoringConfigView.as_view(), 
         name='config'),
    
    # Maintenance operations (admin only)
    path('maintenance/', 
         response_monitoring_views.ResponseMonitoringMaintenanceView.as_view(), 
         name='maintenance'),
    
    # Public health check endpoint
    path('health-check/', 
         response_monitoring_views.response_processing_health_check, 
         name='health_check'),
]