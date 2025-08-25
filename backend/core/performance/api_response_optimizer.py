"""
API Response Time Optimizer - Task 4.3.2

Optimizes API response times through caching, monitoring, and performance optimization.
"""

import time
import logging
from functools import wraps
from typing import Dict, List, Optional, Any, Callable
from django.core.cache import cache
from django.http import JsonResponse
from django.utils import timezone
import hashlib
import json

logger = logging.getLogger(__name__)


class APIResponseOptimizer:
    """
    API response optimization system
    Task 4.3.2: Core response optimization
    """
    
    def __init__(self):
        self.response_times = []
        self.cache_strategies = {
            'aggressive': {'ttl': 3600, 'vary_by': ['user', 'org']},
            'moderate': {'ttl': 900, 'vary_by': ['user']},
            'conservative': {'ttl': 300, 'vary_by': []}
        }
    
    def cached_response(self, ttl: int = 900, vary_by: List[str] = None):
        """
        Decorator for API response caching
        Task 4.3.2: Response caching optimization
        """
        
        def decorator(view_func):
            @wraps(view_func)
            def wrapper(*args, **kwargs):
                # Extract request
                request = None
                if args and hasattr(args[0], 'request'):
                    request = args[0].request
                elif args and hasattr(args[0], 'META'):
                    request = args[0]
                
                if not request or request.method != 'GET':
                    return view_func(*args, **kwargs)
                
                # Generate cache key
                cache_key = self._generate_cache_key(
                    request.path, request.method, request, vary_by or []
                )
                
                # Try cache first
                cached_response = cache.get(cache_key)
                if cached_response:
                    logger.debug(f"Cache hit for {request.path}")
                    return JsonResponse(cached_response)
                
                # Execute and cache
                start_time = time.time()
                response = view_func(*args, **kwargs)
                response_time = time.time() - start_time
                
                # Record performance
                self.response_times.append({
                    'endpoint': request.path,
                    'time': response_time,
                    'cached': False
                })
                
                # Cache successful responses
                if (hasattr(response, 'status_code') and 
                    response.status_code == 200):
                    
                    response_data = None
                    if hasattr(response, 'data'):
                        response_data = response.data
                    elif hasattr(response, 'content'):
                        try:
                            response_data = json.loads(response.content.decode('utf-8'))
                        except:
                            pass
                    
                    if response_data:
                        cache.set(cache_key, response_data, ttl)
                
                return response
            
            return wrapper
        return decorator
    
    def _generate_cache_key(self, endpoint: str, method: str, 
                           request, vary_by: List[str]) -> str:
        """Generate cache key for request"""
        
        key_parts = [endpoint, method]
        
        for vary_param in vary_by:
            if vary_param == 'user' and hasattr(request, 'user') and request.user.is_authenticated:
                key_parts.append(f"user_{request.user.id}")
            elif vary_param == 'org' and hasattr(request, 'user'):
                org_id = getattr(getattr(request.user, 'organization', None), 'id', None)
                if org_id:
                    key_parts.append(f"org_{org_id}")
        
        # Add important query parameters
        for param in ['page', 'limit', 'search', 'filter']:
            if param in request.GET:
                key_parts.append(f"{param}_{request.GET[param]}")
        
        key_string = "_".join(key_parts)
        return f"api_cache_{hashlib.md5(key_string.encode()).hexdigest()}"
    
    def monitor_performance(self, view_func):
        """
        Monitor API performance
        Task 4.3.2: Performance monitoring
        """
        
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            from django.db import connection, reset_queries
            
            reset_queries()
            start_time = time.time()
            
            response = view_func(*args, **kwargs)
            
            execution_time = time.time() - start_time
            query_count = len(connection.queries)
            
            # Log slow responses
            if execution_time > 1.0:
                logger.warning(
                    f"Slow API response: {view_func.__name__} took {execution_time:.3f}s "
                    f"with {query_count} queries"
                )
            
            # Add performance headers
            if hasattr(response, '__setitem__'):
                response['X-Response-Time'] = f"{execution_time:.3f}s"
                response['X-Query-Count'] = str(query_count)
            
            return response
        
        return wrapper
    
    def optimize_queries(self, view_func):
        """
        Optimize database queries
        Task 4.3.2: Query optimization
        """
        
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            # Add query optimization hints
            if hasattr(args[0], 'queryset'):
                # This is a DRF ViewSet
                original_queryset = args[0].queryset
                
                # Apply common optimizations
                if hasattr(original_queryset, 'select_related'):
                    # Auto-select related fields for common patterns
                    fk_fields = []
                    if hasattr(original_queryset.model, '_meta'):
                        for field in original_queryset.model._meta.fields:
                            if hasattr(field, 'related_model'):
                                fk_fields.append(field.name)
                    
                    if fk_fields:
                        args[0].queryset = original_queryset.select_related(*fk_fields[:3])
            
            return view_func(*args, **kwargs)
        
        return wrapper
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get API performance statistics"""
        
        if not self.response_times:
            return {
                'total_requests': 0,
                'avg_response_time': 0,
                'slow_requests': 0
            }
        
        total_requests = len(self.response_times)
        avg_time = sum(r['time'] for r in self.response_times) / total_requests
        slow_requests = sum(1 for r in self.response_times if r['time'] > 1.0)
        
        return {
            'total_requests': total_requests,
            'avg_response_time': avg_time,
            'slow_requests': slow_requests,
            'slow_request_rate': slow_requests / total_requests
        }


# Global optimizer instance
api_optimizer = APIResponseOptimizer()

# Convenience decorators
def cached_api_response(ttl: int = 900):
    """Shortcut for API response caching"""
    return api_optimizer.cached_response(ttl=ttl)

def fast_api_endpoint(view_func):
    """Combined optimization decorator"""
    optimized = view_func
    optimized = api_optimizer.monitor_performance(optimized)
    optimized = api_optimizer.optimize_queries(optimized)
    optimized = api_optimizer.cached_response()(optimized)
    return optimized