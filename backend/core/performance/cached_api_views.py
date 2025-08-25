"""
Cached API Views
Integrates strategic caching and API response optimization for high-performance endpoints
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Q
from datetime import timedelta
import logging

from .strategic_cache_manager import StrategicCacheManager
from .api_response_optimizer import APIResponseOptimizer, cache_api_response, cache_static_data, cache_analytics_data
from permissions.permissions import IsOrgAdminOrSuperAdmin
from core_config.query_performance_middleware import monitor_org_query_performance

# Performance logger
performance_logger = logging.getLogger('performance')

class CachedOrganizationViewSet(viewsets.ViewSet):
    """
    ViewSet for cached organization data with strategic caching
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=True, methods=['get'], url_path='info')
    @cache_static_data(timeout=3600)  # Cache for 1 hour
    @monitor_org_query_performance
    def get_organization_info(self, request, pk=None):
        """
        Get cached organization information
        """
        try:
            organization_id = int(pk)
            
            # Security check
            if not request.user.is_superuser and request.user.organization_id != organization_id:
                return Response(
                    {'error': 'Access denied to organization data'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get cached organization data
            org_data = StrategicCacheManager.get_organization_data(organization_id)
            
            if not org_data:
                return Response(
                    {'error': 'Organization not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            return Response({
                'organization': org_data,
                'cache_info': {
                    'cached': True,
                    'cache_type': 'strategic',
                    'ttl': StrategicCacheManager.ORGANIZATION_TTL
                }
            })
            
        except ValueError:
            return Response(
                {'error': 'Invalid organization ID'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            performance_logger.error(f"Failed to get organization info: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve organization information'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'], url_path='statistics')
    @cache_analytics_data(timeout=900)  # Cache for 15 minutes
    @monitor_org_query_performance
    def get_organization_statistics(self, request, pk=None):
        """
        Get cached organization statistics
        """
        try:
            organization_id = int(pk)
            
            # Security check
            if not request.user.is_superuser and request.user.organization_id != organization_id:
                return Response(
                    {'error': 'Access denied to organization statistics'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get parameters
            days = int(request.query_params.get('days', 30))
            days = min(days, 365)  # Max 1 year
            
            # Get cached deal statistics
            deal_stats = StrategicCacheManager.get_deal_statistics(organization_id, days)
            
            if not deal_stats:
                return Response(
                    {'error': 'Statistics not available'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            return Response({
                'statistics': deal_stats,
                'cache_info': {
                    'cached': True,
                    'cache_type': 'strategic',
                    'ttl': StrategicCacheManager.DEAL_STATS_TTL
                }
            })
            
        except ValueError:
            return Response(
                {'error': 'Invalid parameters'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            performance_logger.error(f"Failed to get organization statistics: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve organization statistics'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'], url_path='roles')
    @cache_static_data(timeout=3600)  # Cache for 1 hour
    @monitor_org_query_performance
    def get_organization_roles(self, request, pk=None):
        """
        Get cached organization role information
        """
        try:
            organization_id = int(pk)
            
            # Security check
            if not request.user.is_superuser and request.user.organization_id != organization_id:
                return Response(
                    {'error': 'Access denied to organization roles'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get cached role information
            role_info = StrategicCacheManager.get_role_information(organization_id)
            
            if not role_info:
                return Response(
                    {'error': 'Role information not available'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            return Response({
                'roles': role_info,
                'cache_info': {
                    'cached': True,
                    'cache_type': 'strategic',
                    'ttl': StrategicCacheManager.ROLE_INFO_TTL
                }
            })
            
        except ValueError:
            return Response(
                {'error': 'Invalid organization ID'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            performance_logger.error(f"Failed to get organization roles: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve organization roles'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CachedUserViewSet(viewsets.ViewSet):
    """
    ViewSet for cached user data and permissions
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['get'], url_path='dashboard')
    @cache_api_response(cache_type='dashboard', timeout=600)  # Cache for 10 minutes
    @monitor_org_query_performance
    def get_user_dashboard(self, request):
        """
        Get cached user dashboard data
        """
        try:
            user = request.user
            
            if not user.organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get optimized dashboard data
            dashboard_data = APIResponseOptimizer.cache_user_dashboard_data(
                user.id, 
                user.organization.id
            )
            
            return Response({
                'dashboard': dashboard_data,
                'cache_info': {
                    'cached': True,
                    'cache_type': 'api_response',
                    'ttl': APIResponseOptimizer.CACHE_TTL['dashboard']
                }
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to get user dashboard: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve dashboard data'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='permissions')
    @cache_api_response(cache_type='user_data', timeout=1800)  # Cache for 30 minutes
    @monitor_org_query_performance
    def get_user_permissions(self, request):
        """
        Get cached user permissions
        """
        try:
            user = request.user
            
            if not user.organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get cached user permissions
            permissions_data = StrategicCacheManager.get_user_permissions(
                user.id, 
                user.organization.id
            )
            
            if not permissions_data:
                return Response(
                    {'error': 'Permissions not available'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            return Response({
                'permissions': permissions_data,
                'cache_info': {
                    'cached': True,
                    'cache_type': 'strategic',
                    'ttl': StrategicCacheManager.USER_PERMISSIONS_TTL
                }
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to get user permissions: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve user permissions'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CachedAnalyticsViewSet(viewsets.ViewSet):
    """
    ViewSet for cached analytics and reporting endpoints
    """
    permission_classes = [IsAuthenticated, IsOrgAdminOrSuperAdmin]
    
    @action(detail=False, methods=['get'], url_path='deal-analytics')
    @cache_analytics_data(timeout=900)  # Cache for 15 minutes
    @monitor_org_query_performance
    def get_deal_analytics(self, request):
        """
        Get cached deal analytics data
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            if not organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get parameters
            days = int(request.query_params.get('days', 30))
            days = min(days, 365)  # Max 1 year
            
            analytics_type = request.query_params.get('type', 'overview')
            
            # Get cached analytics data
            parameters = {'days': days, 'type': analytics_type}
            analytics_data = APIResponseOptimizer.cache_analytics_response(
                'deal_analytics',
                organization.id,
                parameters
            )
            
            # Get actual deal statistics from strategic cache
            deal_stats = StrategicCacheManager.get_deal_statistics(organization.id, days)
            
            # Combine analytics data
            combined_analytics = {
                'overview': deal_stats.get('basic_stats', {}),
                'trends': deal_stats.get('daily_trends', []),
                'source_analysis': deal_stats.get('source_distribution', []),
                'payment_analysis': deal_stats.get('payment_method_distribution', []),
                'top_clients': deal_stats.get('top_clients', []),
                'parameters': parameters,
                'organization': organization.name
            }
            
            return Response({
                'analytics': combined_analytics,
                'cache_info': {
                    'cached': True,
                    'cache_type': 'api_response',
                    'ttl': APIResponseOptimizer.CACHE_TTL['analytics']
                }
            })
            
        except ValueError:
            return Response(
                {'error': 'Invalid parameters'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            performance_logger.error(f"Failed to get deal analytics: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve analytics data'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='performance-metrics')
    @cache_analytics_data(timeout=300)  # Cache for 5 minutes (more frequent updates)
    @monitor_org_query_performance
    def get_performance_metrics(self, request):
        """
        Get cached performance metrics
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            if not organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get cache performance metrics
            cache_metrics = APIResponseOptimizer.get_cache_performance_metrics()
            
            # Get organization statistics for performance context
            org_data = StrategicCacheManager.get_organization_data(organization.id)
            
            performance_data = {
                'cache_performance': cache_metrics,
                'organization_stats': org_data.get('statistics', {}),
                'cache_status': {
                    'strategic_cache': 'active',
                    'api_cache': 'active',
                    'last_updated': timezone.now().isoformat()
                }
            }
            
            return Response({
                'performance': performance_data,
                'cache_info': {
                    'cached': True,
                    'cache_type': 'api_response',
                    'ttl': APIResponseOptimizer.CACHE_TTL['statistics']
                }
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to get performance metrics: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve performance metrics'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CacheManagementViewSet(viewsets.ViewSet):
    """
    ViewSet for cache management operations
    """
    permission_classes = [IsAuthenticated, IsOrgAdminOrSuperAdmin]
    
    @action(detail=False, methods=['post'], url_path='warm-cache')
    @monitor_org_query_performance
    def warm_cache(self, request):
        """
        Warm up caches for organization
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            if not organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Warm strategic caches
            StrategicCacheManager.warm_organization_cache(organization.id)
            
            # Warm API response caches
            APIResponseOptimizer.warm_frequently_accessed_caches(organization.id)
            
            return Response({
                'success': True,
                'message': f'Cache warming initiated for {organization.name}',
                'organization_id': organization.id,
                'warmed_at': timezone.now().isoformat()
            })
            
        except Exception as e:
            performance_logger.error(f"Cache warming failed: {str(e)}")
            return Response(
                {'error': 'Cache warming failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], url_path='invalidate-cache')
    @monitor_org_query_performance
    def invalidate_cache(self, request):
        """
        Invalidate caches for organization
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            if not organization:
                return Response(
                    {'error': 'User must belong to an organization'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            cache_type = request.data.get('cache_type', 'all')
            
            if cache_type == 'strategic' or cache_type == 'all':
                # Invalidate strategic caches
                StrategicCacheManager.invalidate_organization_related_caches(organization.id)
            
            if cache_type == 'api' or cache_type == 'all':
                # Invalidate API response caches
                APIResponseOptimizer.invalidate_api_caches(
                    cache_pattern='all',
                    organization_id=organization.id
                )
            
            if cache_type == 'user':
                # Invalidate user-specific caches
                StrategicCacheManager.invalidate_user_related_caches(user.id, organization.id)
                APIResponseOptimizer.invalidate_api_caches(
                    cache_pattern='dashboard',
                    organization_id=organization.id,
                    user_id=user.id
                )
            
            return Response({
                'success': True,
                'message': f'Cache invalidation completed for {organization.name}',
                'cache_type': cache_type,
                'organization_id': organization.id,
                'invalidated_at': timezone.now().isoformat()
            })
            
        except Exception as e:
            performance_logger.error(f"Cache invalidation failed: {str(e)}")
            return Response(
                {'error': 'Cache invalidation failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], url_path='cache-status')
    @monitor_org_query_performance
    def get_cache_status(self, request):
        """
        Get cache status and statistics
        """
        try:
            user = request.user
            organization = user.organization if hasattr(user, 'organization') else None
            
            # Get cache statistics
            strategic_stats = StrategicCacheManager.get_cache_statistics()
            api_stats = APIResponseOptimizer.get_cache_performance_metrics()
            
            cache_status = {
                'strategic_cache': {
                    'status': 'active',
                    'statistics': strategic_stats
                },
                'api_response_cache': {
                    'status': 'active',
                    'statistics': api_stats
                },
                'organization_id': organization.id if organization else None,
                'user_id': user.id,
                'timestamp': timezone.now().isoformat()
            }
            
            return Response({
                'cache_status': cache_status
            })
            
        except Exception as e:
            performance_logger.error(f"Failed to get cache status: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve cache status'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )