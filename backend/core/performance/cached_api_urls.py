"""
URL configuration for cached API endpoints
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .cached_api_views import (
    CachedOrganizationViewSet,
    CachedUserViewSet,
    CachedAnalyticsViewSet,
    CacheManagementViewSet
)

# Create router for cached API endpoints
router = DefaultRouter()
router.register(r'cached/organizations', CachedOrganizationViewSet, basename='cached-organizations')
router.register(r'cached/users', CachedUserViewSet, basename='cached-users')
router.register(r'cached/analytics', CachedAnalyticsViewSet, basename='cached-analytics')
router.register(r'cache-management', CacheManagementViewSet, basename='cache-management')

urlpatterns = [
    path('api/', include(router.urls)),
]

# Additional URL patterns for specific cached endpoints
cached_patterns = [
    # Organization data endpoints
    path('api/cached/organizations/<int:pk>/info/', 
         CachedOrganizationViewSet.as_view({'get': 'get_organization_info'}),
         name='cached-organization-info'),
    
    path('api/cached/organizations/<int:pk>/statistics/', 
         CachedOrganizationViewSet.as_view({'get': 'get_organization_statistics'}),
         name='cached-organization-statistics'),
    
    path('api/cached/organizations/<int:pk>/roles/', 
         CachedOrganizationViewSet.as_view({'get': 'get_organization_roles'}),
         name='cached-organization-roles'),
    
    # User data endpoints
    path('api/cached/users/dashboard/', 
         CachedUserViewSet.as_view({'get': 'get_user_dashboard'}),
         name='cached-user-dashboard'),
    
    path('api/cached/users/permissions/', 
         CachedUserViewSet.as_view({'get': 'get_user_permissions'}),
         name='cached-user-permissions'),
    
    # Analytics endpoints
    path('api/cached/analytics/deal-analytics/', 
         CachedAnalyticsViewSet.as_view({'get': 'get_deal_analytics'}),
         name='cached-deal-analytics'),
    
    path('api/cached/analytics/performance-metrics/', 
         CachedAnalyticsViewSet.as_view({'get': 'get_performance_metrics'}),
         name='cached-performance-metrics'),
    
    # Cache management endpoints
    path('api/cache-management/warm-cache/', 
         CacheManagementViewSet.as_view({'post': 'warm_cache'}),
         name='warm-cache'),
    
    path('api/cache-management/invalidate-cache/', 
         CacheManagementViewSet.as_view({'post': 'invalidate_cache'}),
         name='invalidate-cache'),
    
    path('api/cache-management/cache-status/', 
         CacheManagementViewSet.as_view({'get': 'get_cache_status'}),
         name='cache-status'),
]

urlpatterns.extend(cached_patterns)