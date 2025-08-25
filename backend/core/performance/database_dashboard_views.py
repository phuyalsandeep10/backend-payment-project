"""
Database Performance Dashboard Views
API endpoints for monitoring and analyzing database performance
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.cache import cache
from django.db import connection
from django.utils import timezone
from core_config.database_optimizer import DatabaseOptimizer, QueryOptimizer, QueryMonitor
from permissions.permissions import IsOrgAdminOrSuperAdmin
import logging
import json

logger = logging.getLogger('database_dashboard')

class DatabasePerformanceDashboardView(APIView):
    """
    Main dashboard view for database performance metrics
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """
        Get comprehensive database performance dashboard data
        """
        try:
            # Get query statistics
            query_stats = QueryMonitor.get_query_statistics()
            
            # Get cached performance data
            performance_data = self._get_cached_performance_data()
            
            # Get optimization recommendations
            recommendations = self._get_optimization_recommendations()
            
            # Get organization-specific data if available
            organization_data = {}
            if hasattr(request.user, 'organization') and request.user.organization:
                organization_data = QueryOptimizer.get_cached_organization_data(
                    request.user.organization.id
                )
            
            dashboard_data = {
                'query_statistics': query_stats,
                'performance_metrics': performance_data,
                'optimization_recommendations': recommendations,
                'organization_data': organization_data,
                'generated_at': timezone.now().isoformat()
            }
            
            return Response(dashboard_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Database dashboard error: {str(e)}")
            return Response(
                {'error': 'Failed to generate dashboard data'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_cached_performance_data(self):
        """
        Get cached performance data from middleware
        """
        try:
            # Get performance stats for common endpoints
            endpoints = [
                '/api/users/',
                '/api/deals/',
                '/api/commissions/',
                '/api/authentication/login/'
            ]
            
            performance_data = {}
            
            for endpoint in endpoints:
                cache_key = f"perf_stats_{endpoint.replace('/', '_')}"
                stats = cache.get(cache_key)
                
                if stats:
                    performance_data[endpoint] = {
                        'total_requests': stats['total_requests'],
                        'avg_time': stats['total_time'] / stats['total_requests'] if stats['total_requests'] > 0 else 0,
                        'avg_queries': stats['total_queries'] / stats['total_requests'] if stats['total_requests'] > 0 else 0,
                        'max_time': stats['max_time'],
                        'max_queries': stats['max_queries']
                    }
            
            return performance_data
            
        except Exception as e:
            logger.error(f"Failed to get cached performance data: {str(e)}")
            return {}
    
    def _get_optimization_recommendations(self):
        """
        Get optimization recommendations
        """
        try:
            # Get missing index recommendations
            missing_indexes = DatabaseOptimizer.get_missing_indexes_recommendations()
            
            recommendations = {
                'missing_indexes': missing_indexes[:5],  # Top 5
                'general_tips': [
                    {
                        'category': 'Query Optimization',
                        'tip': 'Use select_related() for foreign key relationships',
                        'impact': 'Reduces database queries significantly'
                    },
                    {
                        'category': 'Caching',
                        'tip': 'Cache frequently accessed organization data',
                        'impact': 'Improves response times for repeated requests'
                    },
                    {
                        'category': 'Indexing',
                        'tip': 'Add composite indexes for common filter combinations',
                        'impact': 'Speeds up filtered queries and searches'
                    }
                ]
            }
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Failed to get optimization recommendations: {str(e)}")
            return {}


class QueryAnalysisView(APIView):
    """
    View for detailed query analysis
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """
        Get detailed query analysis
        """
        try:
            analysis_type = request.query_params.get('type', 'performance')
            
            if analysis_type == 'performance':
                result = DatabaseOptimizer.analyze_query_performance()
            else:
                result = {'error': f'Unknown analysis type: {analysis_type}'}
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Query analysis error: {str(e)}")
            return Response(
                {'error': 'Failed to analyze queries'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CacheManagementView(APIView):
    """
    View for cache management operations
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def post(self, request):
        """
        Perform cache management operations
        """
        try:
            action = request.data.get('action')
            organization_id = request.data.get('organization_id')
            
            if action == 'warmup':
                if organization_id:
                    org_data = QueryOptimizer.get_cached_organization_data(organization_id)
                    result = {'message': f'Cache warmed up for organization {organization_id}', 'data': org_data}
                else:
                    result = {'error': 'organization_id required for warmup'}
                    
            elif action == 'invalidate':
                if organization_id:
                    QueryOptimizer.invalidate_organization_cache(organization_id)
                    result = {'message': f'Cache invalidated for organization {organization_id}'}
                else:
                    result = {'error': 'organization_id required for invalidation'}
                    
            elif action == 'clear_all':
                cache.clear()
                result = {'message': 'All caches cleared'}
                
            else:
                result = {'error': f'Unknown action: {action}'}
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Cache management error: {str(e)}")
            return Response(
                {'error': 'Cache management operation failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class IndexAnalysisView(APIView):
    """
    View for database index analysis
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """
        Get database index analysis
        """
        try:
            # Get missing index recommendations
            missing_indexes = DatabaseOptimizer.get_missing_indexes_recommendations()
            
            # Get index usage statistics (if available)
            index_usage = self._get_index_usage_stats()
            
            result = {
                'missing_indexes': missing_indexes,
                'index_usage': index_usage,
                'recommendations': self._generate_index_recommendations(missing_indexes, index_usage)
            }
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Index analysis error: {str(e)}")
            return Response(
                {'error': 'Failed to analyze indexes'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_index_usage_stats(self):
        """
        Get index usage statistics from database
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT 
                        schemaname,
                        tablename,
                        indexname,
                        idx_tup_read,
                        idx_tup_fetch
                    FROM pg_stat_user_indexes 
                    ORDER BY idx_tup_read DESC 
                    LIMIT 20
                """)
                
                columns = [col[0] for col in cursor.description]
                results = []
                
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
                
                return results
                
        except Exception as e:
            logger.debug(f"Could not get index usage stats: {str(e)}")
            return []
    
    def _generate_index_recommendations(self, missing_indexes, index_usage):
        """
        Generate index recommendations based on analysis
        """
        recommendations = []
        
        # Recommendations for missing indexes
        for idx in missing_indexes[:3]:  # Top 3
            recommendations.append({
                'type': 'missing_index',
                'priority': 'high',
                'description': f"Add composite index on {idx['model']}: {', '.join(idx['suggested_index'])}",
                'reason': idx['reason']
            })
        
        # Recommendations for unused indexes
        unused_indexes = [idx for idx in index_usage if idx.get('idx_tup_read', 0) < 100]
        if unused_indexes:
            recommendations.append({
                'type': 'unused_indexes',
                'priority': 'medium',
                'description': f"Consider removing {len(unused_indexes)} potentially unused indexes",
                'reason': 'Unused indexes slow down write operations'
            })
        
        return recommendations


class QueryOptimizationTestView(APIView):
    """
    View for testing query optimizations
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def post(self, request):
        """
        Test query optimization performance
        """
        try:
            test_type = request.data.get('test_type', 'user_queries')
            organization_id = request.data.get('organization_id')
            
            if not organization_id:
                return Response(
                    {'error': 'organization_id is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Run optimization tests
            if test_type == 'user_queries':
                result = self._test_user_query_optimization(organization_id)
            elif test_type == 'deal_queries':
                result = self._test_deal_query_optimization(organization_id)
            elif test_type == 'commission_queries':
                result = self._test_commission_query_optimization(organization_id)
            else:
                result = {'error': f'Unknown test type: {test_type}'}
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Query optimization test error: {str(e)}")
            return Response(
                {'error': 'Query optimization test failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _test_user_query_optimization(self, organization_id):
        """
        Test user query optimization
        """
        from apps.authentication.models import User
        from organization.models import Organization
        import time
        
        try:
            organization = Organization.objects.get(id=organization_id)
            
            # Test unoptimized query
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            users_unoptimized = list(User.objects.filter(organization=organization)[:10])
            
            unoptimized_time = time.time() - start_time
            unoptimized_query_count = len(connection.queries) - initial_queries
            
            # Clear query log
            connection.queries_log.clear()
            
            # Test optimized query
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            users_optimized = list(QueryOptimizer.optimize_user_queryset(
                User.objects.filter(organization=organization)
            )[:10])
            
            optimized_time = time.time() - start_time
            optimized_query_count = len(connection.queries) - initial_queries
            
            improvement = 0
            if unoptimized_time > 0:
                improvement = ((unoptimized_time - optimized_time) / unoptimized_time) * 100
            
            return {
                'test_type': 'user_queries',
                'organization_id': organization_id,
                'unoptimized': {
                    'time': unoptimized_time,
                    'query_count': unoptimized_query_count
                },
                'optimized': {
                    'time': optimized_time,
                    'query_count': optimized_query_count
                },
                'improvement_percentage': improvement,
                'records_tested': len(users_optimized)
            }
            
        except Organization.DoesNotExist:
            return {'error': f'Organization {organization_id} not found'}
    
    def _test_deal_query_optimization(self, organization_id):
        """
        Test deal query optimization
        """
        from deals.models import Deal
        from organization.models import Organization
        import time
        
        try:
            organization = Organization.objects.get(id=organization_id)
            
            # Test optimized query
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            deals_optimized = list(QueryOptimizer.optimize_deal_queryset(
                Deal.objects.filter(organization=organization)
            )[:10])
            
            optimized_time = time.time() - start_time
            optimized_query_count = len(connection.queries) - initial_queries
            
            return {
                'test_type': 'deal_queries',
                'organization_id': organization_id,
                'optimized': {
                    'time': optimized_time,
                    'query_count': optimized_query_count
                },
                'records_tested': len(deals_optimized)
            }
            
        except Organization.DoesNotExist:
            return {'error': f'Organization {organization_id} not found'}
    
    def _test_commission_query_optimization(self, organization_id):
        """
        Test commission query optimization
        """
        from commission.models import Commission
        from organization.models import Organization
        import time
        
        try:
            organization = Organization.objects.get(id=organization_id)
            
            # Test optimized query
            start_time = time.time()
            initial_queries = len(connection.queries)
            
            commissions_optimized = list(QueryOptimizer.optimize_commission_queryset(
                Commission.objects.filter(organization=organization)
            )[:10])
            
            optimized_time = time.time() - start_time
            optimized_query_count = len(connection.queries) - initial_queries
            
            return {
                'test_type': 'commission_queries',
                'organization_id': organization_id,
                'optimized': {
                    'time': optimized_time,
                    'query_count': optimized_query_count
                },
                'records_tested': len(commissions_optimized)
            }
            
        except Organization.DoesNotExist:
            return {'error': f'Organization {organization_id} not found'}