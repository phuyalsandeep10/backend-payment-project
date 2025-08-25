"""
Database Performance Monitoring Middleware
Monitors database query performance and provides optimization insights
"""

from django.db import connection
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
import time
import logging
import json

logger = logging.getLogger('database_performance')

class DatabasePerformanceMiddleware:
    """
    Middleware to monitor database query performance and log slow queries
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.slow_query_threshold = getattr(settings, 'SLOW_QUERY_THRESHOLD', 0.1)  # 100ms
        self.log_all_queries = getattr(settings, 'LOG_ALL_QUERIES', False)
        
    def __call__(self, request):
        # Skip monitoring for static files and admin
        if request.path.startswith('/static/') or request.path.startswith('/admin/'):
            return self.get_response(request)
        
        # Record initial state
        start_time = time.time()
        initial_query_count = len(connection.queries)
        
        # Process request
        response = self.get_response(request)
        
        # Calculate performance metrics
        end_time = time.time()
        request_time = end_time - start_time
        query_count = len(connection.queries) - initial_query_count
        
        # Analyze queries if in debug mode
        if settings.DEBUG and query_count > 0:
            self._analyze_queries(request, request_time, query_count, initial_query_count)
        
        # Add performance headers
        response['X-DB-Query-Count'] = str(query_count)
        response['X-DB-Query-Time'] = f"{request_time:.3f}"
        
        return response
    
    def _analyze_queries(self, request, request_time, query_count, initial_query_count):
        """
        Analyze queries for performance issues
        """
        recent_queries = connection.queries[initial_query_count:]
        slow_queries = []
        total_query_time = 0
        
        for query in recent_queries:
            query_time = float(query['time'])
            total_query_time += query_time
            
            if query_time > self.slow_query_threshold:
                slow_queries.append({
                    'sql': query['sql'][:200] + '...' if len(query['sql']) > 200 else query['sql'],
                    'time': query_time
                })
        
        # Log performance metrics
        log_data = {
            'path': request.path,
            'method': request.method,
            'request_time': request_time,
            'query_count': query_count,
            'total_query_time': total_query_time,
            'slow_queries_count': len(slow_queries)
        }
        
        # Log slow requests or high query count
        if request_time > 1.0 or query_count > 20 or slow_queries:
            logger.warning(f"Performance issue detected: {json.dumps(log_data)}")
            
            if slow_queries:
                logger.warning(f"Slow queries detected: {json.dumps(slow_queries[:3])}")
        
        elif self.log_all_queries:
            logger.info(f"Request performance: {json.dumps(log_data)}")
        
        # Update performance statistics cache
        self._update_performance_stats(request.path, request_time, query_count)
    
    def _update_performance_stats(self, path, request_time, query_count):
        """
        Update cached performance statistics
        """
        cache_key = f"perf_stats_{path.replace('/', '_')}"
        stats = cache.get(cache_key, {
            'total_requests': 0,
            'total_time': 0,
            'total_queries': 0,
            'max_time': 0,
            'max_queries': 0
        })
        
        stats['total_requests'] += 1
        stats['total_time'] += request_time
        stats['total_queries'] += query_count
        stats['max_time'] = max(stats['max_time'], request_time)
        stats['max_queries'] = max(stats['max_queries'], query_count)
        
        # Cache for 1 hour
        cache.set(cache_key, stats, 3600)


class QueryCountLimitMiddleware:
    """
    Middleware to limit the number of database queries per request
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.query_limit = getattr(settings, 'MAX_QUERIES_PER_REQUEST', 50)
        
    def __call__(self, request):
        initial_query_count = len(connection.queries)
        
        response = self.get_response(request)
        
        query_count = len(connection.queries) - initial_query_count
        
        if query_count > self.query_limit:
            logger.error(
                f"Query limit exceeded: {query_count} queries for {request.path} "
                f"(limit: {self.query_limit})"
            )
            
            # Add warning header
            response['X-DB-Query-Warning'] = f"Query limit exceeded: {query_count}/{self.query_limit}"
        
        return response


class DatabaseConnectionPoolMiddleware:
    """
    Middleware to monitor database connection pool usage
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Monitor connection pool before request
        self._log_connection_stats('before_request')
        
        response = self.get_response(request)
        
        # Monitor connection pool after request
        self._log_connection_stats('after_request')
        
        return response
    
    def _log_connection_stats(self, stage):
        """
        Log database connection statistics
        """
        try:
            # Get connection info (this is database-specific)
            with connection.cursor() as cursor:
                cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE state = 'active'")
                active_connections = cursor.fetchone()[0]
                
                cursor.execute("SELECT count(*) FROM pg_stat_activity")
                total_connections = cursor.fetchone()[0]
                
                logger.debug(f"DB connections {stage}: {active_connections} active, {total_connections} total")
                
        except Exception as e:
            logger.debug(f"Could not get connection stats: {str(e)}")


class QueryOptimizationMiddleware:
    """
    Middleware to automatically apply query optimizations
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Add query optimization hints to request
        request.db_optimization_enabled = True
        request.use_select_related = True
        request.use_prefetch_related = True
        
        response = self.get_response(request)
        
        return response