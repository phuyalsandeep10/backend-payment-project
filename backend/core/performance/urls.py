"""
URL Configuration for Core Performance Module

Task 2.2.3 - Core Config Decomposition
"""

from django.urls import path, include

app_name = 'performance'

urlpatterns = [
    # Cached API endpoints
    path('cache/', include('core.performance.cached_api_urls')),
    
    # Cache performance monitoring (Task 4.1.1)
    path('cache/', include('core.performance.cache_urls')),
    
    # Database performance dashboard
    path('database/', include('core.performance.database_urls')),
]
