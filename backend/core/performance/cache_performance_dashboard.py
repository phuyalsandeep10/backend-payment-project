"""
Cache Performance Dashboard - Task 4.1.1

Web dashboard for monitoring cache performance baselines and real-time metrics.
Provides visual analytics and baseline establishment tools.
"""

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.views.generic import TemplateView
from django.contrib.admin.views.decorators import staff_member_required
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from datetime import datetime, timedelta
from typing import Dict, Any, List
import json
import logging

from .cache_performance_monitor import cache_performance_collector, cache_instrumentation

logger = logging.getLogger(__name__)


@method_decorator(staff_member_required, name='dispatch')
class CachePerformanceDashboard(TemplateView):
    """
    Main cache performance dashboard view
    Task 4.1.1: Performance monitoring dashboard
    """
    
    template_name = 'core/performance/cache_dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Get baseline statistics
        baseline_stats = cache_performance_collector.get_baseline_stats()
        
        # Get performance trends
        trends = cache_performance_collector.get_performance_trends()
        
        # Get slow operations
        slow_operations = cache_performance_collector.get_slow_operations(10)
        
        # Get key analytics
        key_analytics = cache_performance_collector.get_cache_key_analytics()
        
        context.update({
            'baseline_stats': baseline_stats,
            'trends': trends,
            'slow_operations': slow_operations,
            'key_analytics': key_analytics,
            'dashboard_title': 'Cache Performance Baseline Dashboard',
            'last_updated': datetime.now(),
            'monitoring_active': cache_instrumentation._instrumented
        })
        
        return context


@staff_member_required
@csrf_exempt
def cache_metrics_api(request):
    """
    API endpoint for real-time cache metrics
    Task 4.1.1: Real-time metrics API
    """
    
    if request.method == 'GET':
        timeframe = int(request.GET.get('timeframe', 60))  # minutes
        
        try:
            baseline_stats = cache_performance_collector.get_baseline_stats(timeframe)
            
            response_data = {
                'success': True,
                'data': {
                    'total_operations': baseline_stats.total_operations,
                    'hit_count': baseline_stats.hit_count,
                    'miss_count': baseline_stats.miss_count,
                    'hit_rate': baseline_stats.hit_rate,
                    'avg_response_time': baseline_stats.avg_response_time,
                    'operations_per_second': baseline_stats.operations_per_second,
                    'total_data_transferred': baseline_stats.total_data_transferred,
                    'timeframe_minutes': timeframe,
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            return JsonResponse(response_data)
            
        except Exception as e:
            logger.error(f"Error getting cache metrics: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@staff_member_required
@csrf_exempt  
def cache_trends_api(request):
    """
    API endpoint for cache performance trends
    Task 4.1.1: Trend analysis API
    """
    
    if request.method == 'GET':
        hours = int(request.GET.get('hours', 24))
        
        try:
            trends = cache_performance_collector.get_performance_trends(hours)
            
            response_data = {
                'success': True,
                'data': trends,
                'timeframe_hours': hours,
                'timestamp': datetime.now().isoformat()
            }
            
            return JsonResponse(response_data)
            
        except Exception as e:
            logger.error(f"Error getting cache trends: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@staff_member_required
@csrf_exempt
def cache_baseline_export(request):
    """
    Export cache performance baseline report
    Task 4.1.1: Baseline export functionality
    """
    
    if request.method == 'POST':
        try:
            # Generate baseline report
            report = cache_performance_collector.export_baseline_report()
            
            # Create filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cache_baseline_report_{timestamp}.json"
            
            # Return as downloadable JSON file
            response = HttpResponse(
                json.dumps(report, indent=2, default=str),
                content_type='application/json'
            )
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            logger.info(f"Cache baseline report exported: {filename}")
            return response
            
        except Exception as e:
            logger.error(f"Error exporting baseline report: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@staff_member_required
@csrf_exempt
def cache_monitoring_control(request):
    """
    Control cache monitoring (start/stop/reset)
    Task 4.1.1: Monitoring control API
    """
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
            
            if action == 'start':
                if not cache_instrumentation._instrumented:
                    cache_instrumentation.instrument_cache()
                    message = "Cache monitoring started"
                else:
                    message = "Cache monitoring already active"
                    
            elif action == 'stop':
                if cache_instrumentation._instrumented:
                    cache_instrumentation.restore_cache()
                    message = "Cache monitoring stopped"
                else:
                    message = "Cache monitoring not active"
                    
            elif action == 'reset':
                cache_performance_collector.reset_metrics()
                message = "Cache metrics reset"
                
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid action. Use: start, stop, or reset'
                }, status=400)
            
            return JsonResponse({
                'success': True,
                'message': message,
                'monitoring_active': cache_instrumentation._instrumented
            })
            
        except Exception as e:
            logger.error(f"Error controlling cache monitoring: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@staff_member_required
def cache_key_analytics_api(request):
    """
    API endpoint for cache key pattern analytics
    Task 4.1.1: Key-level performance analysis
    """
    
    if request.method == 'GET':
        try:
            key_analytics = cache_performance_collector.get_cache_key_analytics()
            
            # Sort by total operations (hit + miss)
            sorted_analytics = sorted(
                key_analytics.items(),
                key=lambda x: x[1]['hit_count'] + x[1]['miss_count'],
                reverse=True
            )
            
            # Prepare response data
            formatted_analytics = []
            for pattern, stats in sorted_analytics[:20]:  # Top 20 patterns
                formatted_analytics.append({
                    'pattern': pattern,
                    'hit_count': stats['hit_count'],
                    'miss_count': stats['miss_count'],
                    'hit_rate': stats['hit_rate'],
                    'avg_time': stats['avg_time'],
                    'data_size': stats['data_size'],
                    'last_accessed': stats['last_accessed'].isoformat() if stats['last_accessed'] else None
                })
            
            response_data = {
                'success': True,
                'data': formatted_analytics,
                'total_patterns': len(key_analytics),
                'timestamp': datetime.now().isoformat()
            }
            
            return JsonResponse(response_data)
            
        except Exception as e:
            logger.error(f"Error getting key analytics: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@staff_member_required
def slow_operations_api(request):
    """
    API endpoint for slow cache operations analysis
    Task 4.1.1: Slow operation identification
    """
    
    if request.method == 'GET':
        limit = int(request.GET.get('limit', 20))
        
        try:
            slow_operations = cache_performance_collector.get_slow_operations(limit)
            
            # Format slow operations for response
            formatted_operations = []
            for op in slow_operations:
                formatted_operations.append({
                    'operation': op.operation,
                    'key': op.key,
                    'execution_time': op.execution_time,
                    'data_size': op.data_size,
                    'timestamp': op.timestamp.isoformat(),
                    'cache_backend': op.cache_backend
                })
            
            response_data = {
                'success': True,
                'data': formatted_operations,
                'limit': limit,
                'timestamp': datetime.now().isoformat()
            }
            
            return JsonResponse(response_data)
            
        except Exception as e:
            logger.error(f"Error getting slow operations: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


def cache_health_check(request):
    """
    Simple cache health check endpoint
    Task 4.1.1: Cache health monitoring
    """
    
    try:
        from django.core.cache import cache
        
        # Test basic cache operations
        test_key = 'health_check_test'
        test_value = 'test_value'
        
        # Test set
        start_time = datetime.now()
        cache.set(test_key, test_value, 30)
        set_time = (datetime.now() - start_time).total_seconds()
        
        # Test get
        start_time = datetime.now()
        retrieved_value = cache.get(test_key)
        get_time = (datetime.now() - start_time).total_seconds()
        
        # Test delete
        start_time = datetime.now()
        cache.delete(test_key)
        delete_time = (datetime.now() - start_time).total_seconds()
        
        # Determine health status
        max_acceptable_time = 0.1  # 100ms
        is_healthy = (
            retrieved_value == test_value and
            set_time < max_acceptable_time and
            get_time < max_acceptable_time and
            delete_time < max_acceptable_time
        )
        
        baseline_stats = cache_performance_collector.get_baseline_stats(5)  # Last 5 minutes
        
        health_data = {
            'status': 'healthy' if is_healthy else 'degraded',
            'cache_operations': {
                'set_time': set_time,
                'get_time': get_time,
                'delete_time': delete_time,
                'total_time': set_time + get_time + delete_time
            },
            'baseline_metrics': {
                'hit_rate': baseline_stats.hit_rate,
                'avg_response_time': baseline_stats.avg_response_time,
                'operations_per_second': baseline_stats.operations_per_second
            },
            'monitoring_active': cache_instrumentation._instrumented,
            'timestamp': datetime.now().isoformat()
        }
        
        status_code = 200 if is_healthy else 503
        return JsonResponse(health_data, status=status_code)
        
    except Exception as e:
        logger.error(f"Cache health check failed: {e}")
        return JsonResponse({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }, status=503)
