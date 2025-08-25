"""
Query Performance Monitoring Middleware
Monitors database query performance for organization-scoped operations
"""

import time
import logging
from django.db import connection
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

# Performance logger
performance_logger = logging.getLogger('performance')

class QueryPerformanceMiddleware(MiddlewareMixin):
    """
    Middleware to monitor query performance for organization-scoped operations
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """Start monitoring queries at the beginning of request"""
        try:
            if settings.DEBUG or getattr(settings, 'MONITOR_QUERY_PERFORMANCE', False):
                request._query_start_time = time.time()
                request._query_count_start = len(connection.queries)
        except Exception as e:
            # Handle errors gracefully - don't break the request
            performance_logger.error(f"Error starting query monitoring: {str(e)}")
    
    def process_response(self, request, response):
        """Monitor and log query performance at the end of request"""
        try:
            if not hasattr(request, '_query_start_time'):
                return response
            
            # Calculate query metrics
            query_time = time.time() - request._query_start_time
            query_count = len(connection.queries) - request._query_count_start
            
            # Only log if we have significant query activity or slow queries
            if query_count > 5 or query_time > 0.1:  # More than 5 queries or slower than 100ms
                self._log_query_performance(request, response, query_time, query_count)
            
            # Log organization-scoped queries specifically
            if hasattr(request, 'user') and request.user.is_authenticated:
                self._analyze_organization_queries(request, query_time, query_count)
            
        except Exception as e:
            # Handle errors gracefully - don't break the response
            performance_logger.error(
                f"Error in query performance monitoring for {request.path}: {type(e).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'QueryPerformanceMiddleware',
                    'exception_type': type(e).__name__,
                    'exception_message': str(e)
                }
            )
        
        return response
    
    def _log_query_performance(self, request, response, query_time, query_count):
        """Log general query performance"""
        performance_logger.info(
            f"Query Performance - Path: {request.path}, "
            f"Method: {request.method}, "
            f"Queries: {query_count}, "
            f"Time: {query_time:.3f}s, "
            f"Status: {response.status_code}"
        )
        
        # Log slow queries in detail if in debug mode
        if settings.DEBUG and query_time > 0.5:  # Queries slower than 500ms
            slow_queries = [
                q for q in connection.queries[-query_count:] 
                if float(q['time']) > 0.1  # Individual queries slower than 100ms
            ]
            
            for query in slow_queries:
                performance_logger.warning(
                    f"Slow Query - Time: {query['time']}s, "
                    f"SQL: {query['sql'][:200]}..."
                )
    
    def _analyze_organization_queries(self, request, query_time, query_count):
        """Analyze organization-scoped query patterns"""
        user = request.user
        
        # Check if this is an organization-scoped request
        is_org_scoped = (
            hasattr(user, 'organization') and user.organization and
            not user.is_superuser
        )
        
        if is_org_scoped:
            # Log organization-specific performance
            performance_logger.info(
                f"Org-Scoped Query - Org: {user.organization.name}, "
                f"User: {user.email}, "
                f"Path: {request.path}, "
                f"Queries: {query_count}, "
                f"Time: {query_time:.3f}s"
            )
            
            # Check for potential N+1 query problems
            if query_count > 10:
                performance_logger.warning(
                    f"Potential N+1 Query Issue - Org: {user.organization.name}, "
                    f"Path: {request.path}, "
                    f"Queries: {query_count}"
                )
            
            # Analyze organization-related queries
            if settings.DEBUG:
                self._analyze_org_query_patterns(request, user.organization)
    
    def _analyze_org_query_patterns(self, request, organization):
        """Analyze specific organization query patterns for optimization opportunities"""
        recent_queries = connection.queries[-10:]  # Last 10 queries
        
        org_related_queries = []
        for query in recent_queries:
            sql = query['sql'].lower()
            if any(table in sql for table in [
                'authentication_user', 'deals_deal', 'organization_organization',
                'permissions_role', 'commission_commission'
            ]):
                org_related_queries.append(query)
        
        if len(org_related_queries) > 5:
            performance_logger.info(
                f"High Org Query Activity - Org: {organization.name}, "
                f"Org Queries: {len(org_related_queries)}, "
                f"Path: {request.path}"
            )
            
            # Check for missing organization filters
            unfiltered_queries = [
                q for q in org_related_queries 
                if 'organization' not in q['sql'].lower() and 'WHERE' in q['sql'].upper()
            ]
            
            if unfiltered_queries:
                performance_logger.warning(
                    f"Potential Unfiltered Org Queries - Org: {organization.name}, "
                    f"Count: {len(unfiltered_queries)}, "
                    f"Path: {request.path}"
                )


class OrganizationQueryOptimizer:
    """
    Utility class for optimizing organization-scoped queries
    """
    
    @staticmethod
    def optimize_user_queryset(queryset, organization=None):
        """
        Optimize user queryset for organization-scoped operations
        """
        optimized = queryset.select_related(
            'organization',
            'role',
            'team'
        ).prefetch_related(
            'role__permissions',
            'secure_sessions'
        )
        
        if organization:
            optimized = optimized.filter(organization_id=organization.id)
        
        return optimized
    
    @staticmethod
    def optimize_deal_queryset(queryset, organization=None):
        """
        Optimize deal queryset for organization-scoped operations
        """
        optimized = queryset.select_related(
            'organization',
            'client',
            'project',
            'created_by',
            'updated_by'
        ).prefetch_related(
            'payments',
            'approvals',
            'activity_logs'
        )
        
        if organization:
            optimized = optimized.filter(organization_id=organization.id)
        
        return optimized
    
    @staticmethod
    def get_organization_stats(organization):
        """
        Get organization statistics with optimized queries
        """
        from apps.authentication.models import User
        from deals.models import Deal
        from django.db.models import Count, Sum, Avg
        
        # Use efficient aggregation queries
        stats = {
            'user_count': User.objects.filter(organization_id=organization.id, is_active=True).count(),
            'deal_count': Deal.objects.filter(organization_id=organization.id).count(),
            'total_deal_value': Deal.objects.filter(
                organization_id=organization.id
            ).aggregate(total=Sum('deal_value'))['total'] or 0,
            'avg_deal_value': Deal.objects.filter(
                organization_id=organization.id
            ).aggregate(avg=Avg('deal_value'))['avg'] or 0,
        }
        
        return stats


# Query performance monitoring decorator
def monitor_org_query_performance(func):
    """
    Decorator to monitor query performance for organization-scoped operations
    """
    def wrapper(*args, **kwargs):
        if not (settings.DEBUG or getattr(settings, 'MONITOR_QUERY_PERFORMANCE', False)):
            return func(*args, **kwargs)
        
        start_time = time.time()
        start_queries = len(connection.queries)
        
        try:
            result = func(*args, **kwargs)
            
            end_time = time.time()
            end_queries = len(connection.queries)
            
            query_time = end_time - start_time
            query_count = end_queries - start_queries
            
            if query_count > 3 or query_time > 0.05:  # More than 3 queries or slower than 50ms
                performance_logger.info(
                    f"Function Performance - {func.__name__}: "
                    f"Queries: {query_count}, Time: {query_time:.3f}s"
                )
            
            return result
            
        except Exception as e:
            performance_logger.error(
                f"Function Error - {func.__name__}: {str(e)}"
            )
            raise
    
    return wrapper