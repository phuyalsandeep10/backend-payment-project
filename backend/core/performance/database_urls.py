"""
URL patterns for database performance monitoring and optimization
"""

from django.urls import path
from .database_dashboard_views import (
    DatabasePerformanceDashboardView,
    QueryAnalysisView,
    CacheManagementView,
    IndexAnalysisView,
    QueryOptimizationTestView
)

urlpatterns = [
    # Database performance dashboard
    path('database/dashboard/', DatabasePerformanceDashboardView.as_view(), name='database-dashboard'),
    
    # Query analysis
    path('database/query-analysis/', QueryAnalysisView.as_view(), name='query-analysis'),
    
    # Cache management
    path('database/cache-management/', CacheManagementView.as_view(), name='cache-management'),
    
    # Index analysis
    path('database/index-analysis/', IndexAnalysisView.as_view(), name='index-analysis'),
    
    # Query optimization testing
    path('database/optimization-test/', QueryOptimizationTestView.as_view(), name='optimization-test'),
]