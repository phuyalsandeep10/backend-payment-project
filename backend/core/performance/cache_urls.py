"""
Cache Performance URLs - Task 4.1.1

URL patterns for cache performance monitoring and baseline establishment.
"""

from django.urls import path
from . import cache_performance_dashboard

app_name = 'cache_performance'

urlpatterns = [
    # Cache Performance Dashboard
    path(
        'dashboard/',
        cache_performance_dashboard.CachePerformanceDashboard.as_view(),
        name='dashboard'
    ),
    
    # API Endpoints
    path(
        'api/metrics/',
        cache_performance_dashboard.cache_metrics_api,
        name='metrics_api'
    ),
    
    path(
        'api/trends/',
        cache_performance_dashboard.cache_trends_api,
        name='trends_api'
    ),
    
    path(
        'api/keys/analytics/',
        cache_performance_dashboard.cache_key_analytics_api,
        name='key_analytics_api'
    ),
    
    path(
        'api/slow-operations/',
        cache_performance_dashboard.slow_operations_api,
        name='slow_operations_api'
    ),
    
    # Control Endpoints
    path(
        'control/',
        cache_performance_dashboard.cache_monitoring_control,
        name='monitoring_control'
    ),
    
    path(
        'baseline/export/',
        cache_performance_dashboard.cache_baseline_export,
        name='baseline_export'
    ),
    
    # Health Check
    path(
        'health/',
        cache_performance_dashboard.cache_health_check,
        name='health_check'
    ),
    
    # Cache Invalidation Monitoring (Task 4.1.2)
    path(
        'invalidation/metrics/',
        'core.performance.cache_invalidation_monitor.invalidation_metrics_api',
        name='invalidation_metrics'
    ),
    
    path(
        'invalidation/control/',
        'core.performance.cache_invalidation_monitor.invalidation_control_api',
        name='invalidation_control'
    ),
    
    path(
        'invalidation/analytics/',
        'core.performance.cache_invalidation_monitor.invalidation_analytics_api',
        name='invalidation_analytics'
    ),
]
