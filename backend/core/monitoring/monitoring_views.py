"""
Monitoring Views
API endpoints for performance monitoring and alerting system
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views import View
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
import json
import logging

from .performance_monitor import performance_monitor
from core_config.utils.decorators import require_organization_access, require_admin_access

logger = logging.getLogger(__name__)

class PerformanceMonitoringView(View):
    """Base view for performance monitoring endpoints"""
    
    @method_decorator(login_required)
    @method_decorator(require_organization_access)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

@method_decorator(csrf_exempt, name='dispatch')
class PerformanceSummaryView(PerformanceMonitoringView):
    """Get performance summary for specified time period"""
    
    def get(self, request):
        try:
            # Get time period from query params (default 1 hour)
            hours = int(request.GET.get('hours', 1))
            hours = min(hours, 24)  # Limit to 24 hours max
            
            # Get performance summary
            summary = performance_monitor.get_performance_summary(hours=hours)
            
            return JsonResponse({
                'success': True,
                'data': summary
            })
            
        except Exception as e:
            logger.error(f"Error getting performance summary: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve performance summary'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class SlowQueriesView(PerformanceMonitoringView):
    """Get slow database queries"""
    
    def get(self, request):
        try:
            limit = int(request.GET.get('limit', 50))
            limit = min(limit, 200)  # Limit to 200 max
            
            slow_queries = performance_monitor.get_slow_queries(limit=limit)
            
            return JsonResponse({
                'success': True,
                'data': {
                    'slow_queries': slow_queries,
                    'count': len(slow_queries)
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting slow queries: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve slow queries'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class SlowAPICallsView(PerformanceMonitoringView):
    """Get slow API calls"""
    
    def get(self, request):
        try:
            limit = int(request.GET.get('limit', 50))
            limit = min(limit, 200)  # Limit to 200 max
            
            slow_calls = performance_monitor.get_slow_api_calls(limit=limit)
            
            return JsonResponse({
                'success': True,
                'data': {
                    'slow_api_calls': slow_calls,
                    'count': len(slow_calls)
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting slow API calls: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve slow API calls'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class PerformanceTrendsView(PerformanceMonitoringView):
    """Get performance trends over time"""
    
    def get(self, request):
        try:
            hours = int(request.GET.get('hours', 24))
            hours = min(hours, 168)  # Limit to 1 week max
            
            trends = performance_monitor.get_performance_trends(hours=hours)
            
            return JsonResponse({
                'success': True,
                'data': trends
            })
            
        except Exception as e:
            logger.error(f"Error getting performance trends: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve performance trends'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class PerformanceAlertsView(PerformanceMonitoringView):
    """Get performance alerts"""
    
    def get(self, request):
        try:
            hours = int(request.GET.get('hours', 24))
            hours = min(hours, 168)  # Limit to 1 week max
            
            cutoff_time = timezone.now() - timedelta(hours=hours)
            cutoff_str = cutoff_time.isoformat()
            
            # Filter alerts by time
            recent_alerts = [
                alert for alert in performance_monitor.performance_alerts 
                if alert['timestamp'] >= cutoff_str
            ]
            
            # Group alerts by type
            alerts_by_type = {}
            for alert in recent_alerts:
                alert_type = alert['type']
                if alert_type not in alerts_by_type:
                    alerts_by_type[alert_type] = []
                alerts_by_type[alert_type].append(alert)
            
            return JsonResponse({
                'success': True,
                'data': {
                    'alerts': recent_alerts,
                    'alerts_by_type': alerts_by_type,
                    'total_alerts': len(recent_alerts),
                    'period_hours': hours
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting performance alerts: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve performance alerts'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class SystemMetricsView(PerformanceMonitoringView):
    """Get current system metrics"""
    
    def get(self, request):
        try:
            # Get latest system metrics
            latest_metrics = list(performance_monitor.system_metrics)[-1] if performance_monitor.system_metrics else {}
            
            return JsonResponse({
                'success': True,
                'data': {
                    'current_metrics': latest_metrics,
                    'thresholds': {
                        'cpu_warning': performance_monitor.CPU_WARNING_THRESHOLD,
                        'memory_warning': performance_monitor.MEMORY_WARNING_THRESHOLD,
                        'slow_query_threshold': performance_monitor.SLOW_QUERY_THRESHOLD,
                        'slow_api_threshold': performance_monitor.SLOW_API_THRESHOLD
                    }
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting system metrics: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve system metrics'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class DatabaseMetricsView(PerformanceMonitoringView):
    """Get database-specific performance metrics"""
    
    def get(self, request):
        try:
            from django.db import connection
            
            # Get database connection info
            db_info = {
                'vendor': connection.vendor,
                'queries_count': len(connection.queries),
                'total_queries': performance_monitor.total_queries,
                'slow_queries': performance_monitor.slow_queries,
                'slow_query_rate': (performance_monitor.slow_queries / performance_monitor.total_queries * 100) if performance_monitor.total_queries > 0 else 0
            }
            
            # Get recent query metrics
            hours = int(request.GET.get('hours', 1))
            cutoff_time = timezone.now() - timedelta(hours=hours)
            cutoff_str = cutoff_time.isoformat()
            
            recent_queries = [
                q for q in performance_monitor.query_metrics 
                if q['timestamp'] >= cutoff_str
            ]
            
            # Calculate query statistics
            if recent_queries:
                execution_times = [q['execution_time'] for q in recent_queries]
                avg_time = sum(execution_times) / len(execution_times)
                max_time = max(execution_times)
                min_time = min(execution_times)
                slow_count = len([q for q in recent_queries if q['is_slow']])
            else:
                avg_time = max_time = min_time = slow_count = 0
            
            return JsonResponse({
                'success': True,
                'data': {
                    'database_info': db_info,
                    'recent_performance': {
                        'period_hours': hours,
                        'total_queries': len(recent_queries),
                        'slow_queries': slow_count,
                        'avg_execution_time': avg_time,
                        'max_execution_time': max_time,
                        'min_execution_time': min_time,
                        'slow_query_rate': (slow_count / len(recent_queries) * 100) if recent_queries else 0
                    }
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting database metrics: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve database metrics'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class APIMetricsView(PerformanceMonitoringView):
    """Get API-specific performance metrics"""
    
    def get(self, request):
        try:
            hours = int(request.GET.get('hours', 1))
            cutoff_time = timezone.now() - timedelta(hours=hours)
            cutoff_str = cutoff_time.isoformat()
            
            # Get recent API metrics
            recent_api_calls = [
                a for a in performance_monitor.api_metrics 
                if a['timestamp'] >= cutoff_str
            ]
            
            # Calculate API statistics
            if recent_api_calls:
                response_times = [a['response_time'] for a in recent_api_calls]
                avg_time = sum(response_times) / len(response_times)
                max_time = max(response_times)
                min_time = min(response_times)
                slow_count = len([a for a in recent_api_calls if a['is_slow']])
                error_count = len([a for a in recent_api_calls if a['status_code'] >= 400])
                
                # Group by endpoint
                endpoint_stats = {}
                for call in recent_api_calls:
                    endpoint = f"{call['method']} {call['endpoint']}"
                    if endpoint not in endpoint_stats:
                        endpoint_stats[endpoint] = {
                            'count': 0,
                            'total_time': 0,
                            'errors': 0,
                            'slow_calls': 0
                        }
                    
                    endpoint_stats[endpoint]['count'] += 1
                    endpoint_stats[endpoint]['total_time'] += call['response_time']
                    if call['status_code'] >= 400:
                        endpoint_stats[endpoint]['errors'] += 1
                    if call['is_slow']:
                        endpoint_stats[endpoint]['slow_calls'] += 1
                
                # Calculate averages for endpoints
                for endpoint, stats in endpoint_stats.items():
                    stats['avg_time'] = stats['total_time'] / stats['count']
                    stats['error_rate'] = (stats['errors'] / stats['count']) * 100
                    stats['slow_call_rate'] = (stats['slow_calls'] / stats['count']) * 100
                    del stats['total_time']  # Remove intermediate calculation
                
            else:
                avg_time = max_time = min_time = slow_count = error_count = 0
                endpoint_stats = {}
            
            return JsonResponse({
                'success': True,
                'data': {
                    'period_hours': hours,
                    'summary': {
                        'total_api_calls': len(recent_api_calls),
                        'slow_api_calls': slow_count,
                        'error_calls': error_count,
                        'avg_response_time': avg_time,
                        'max_response_time': max_time,
                        'min_response_time': min_time,
                        'slow_call_rate': (slow_count / len(recent_api_calls) * 100) if recent_api_calls else 0,
                        'error_rate': (error_count / len(recent_api_calls) * 100) if recent_api_calls else 0
                    },
                    'by_endpoint': endpoint_stats
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting API metrics: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve API metrics'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(require_admin_access, name='dispatch')
class PerformanceConfigView(PerformanceMonitoringView):
    """Configure performance monitoring thresholds (admin only)"""
    
    def get(self, request):
        """Get current configuration"""
        try:
            config = {
                'slow_query_threshold': performance_monitor.SLOW_QUERY_THRESHOLD,
                'slow_api_threshold': performance_monitor.SLOW_API_THRESHOLD,
                'memory_warning_threshold': performance_monitor.MEMORY_WARNING_THRESHOLD,
                'cpu_warning_threshold': performance_monitor.CPU_WARNING_THRESHOLD,
                'metrics_retention_hours': performance_monitor.METRICS_RETENTION_HOURS
            }
            
            return JsonResponse({
                'success': True,
                'data': config
            })
            
        except Exception as e:
            logger.error(f"Error getting performance config: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve performance configuration'
            }, status=500)
    
    def post(self, request):
        """Update configuration"""
        try:
            data = json.loads(request.body)
            
            # Update thresholds if provided
            if 'slow_query_threshold' in data:
                performance_monitor.SLOW_QUERY_THRESHOLD = float(data['slow_query_threshold'])
            
            if 'slow_api_threshold' in data:
                performance_monitor.SLOW_API_THRESHOLD = float(data['slow_api_threshold'])
            
            if 'memory_warning_threshold' in data:
                performance_monitor.MEMORY_WARNING_THRESHOLD = float(data['memory_warning_threshold'])
            
            if 'cpu_warning_threshold' in data:
                performance_monitor.CPU_WARNING_THRESHOLD = float(data['cpu_warning_threshold'])
            
            if 'metrics_retention_hours' in data:
                performance_monitor.METRICS_RETENTION_HOURS = int(data['metrics_retention_hours'])
            
            logger.info(f"Performance monitoring configuration updated by user {request.user.id}")
            
            return JsonResponse({
                'success': True,
                'message': 'Configuration updated successfully'
            })
            
        except Exception as e:
            logger.error(f"Error updating performance config: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to update performance configuration'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(require_admin_access, name='dispatch')
class PerformanceMaintenanceView(PerformanceMonitoringView):
    """Performance monitoring maintenance operations (admin only)"""
    
    def post(self, request):
        """Perform maintenance operations"""
        try:
            data = json.loads(request.body)
            operation = data.get('operation')
            
            if operation == 'clear_old_metrics':
                performance_monitor.clear_old_metrics()
                message = 'Old metrics cleared successfully'
                
            elif operation == 'reset_counters':
                performance_monitor.total_queries = 0
                performance_monitor.slow_queries = 0
                performance_monitor.total_api_calls = 0
                performance_monitor.slow_api_calls = 0
                performance_monitor.error_metrics.clear()
                message = 'Performance counters reset successfully'
                
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid operation'
                }, status=400)
            
            logger.info(f"Performance maintenance operation '{operation}' performed by user {request.user.id}")
            
            return JsonResponse({
                'success': True,
                'message': message
            })
            
        except Exception as e:
            logger.error(f"Error performing maintenance: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to perform maintenance operation'
            }, status=500)

# Health check endpoint (no authentication required)
@require_http_methods(["GET"])
def health_check(request):
    """System health check endpoint"""
    try:
        # Get latest system metrics
        latest_metrics = list(performance_monitor.system_metrics)[-1] if performance_monitor.system_metrics else {}
        
        # Determine health status
        health_status = 'healthy'
        issues = []
        
        if latest_metrics:
            if latest_metrics.get('cpu_percent', 0) > performance_monitor.CPU_WARNING_THRESHOLD:
                health_status = 'warning'
                issues.append(f"High CPU usage: {latest_metrics['cpu_percent']:.1f}%")
            
            if latest_metrics.get('memory_percent', 0) > performance_monitor.MEMORY_WARNING_THRESHOLD:
                health_status = 'warning'
                issues.append(f"High memory usage: {latest_metrics['memory_percent']:.1f}%")
            
            if latest_metrics.get('disk_percent', 0) > 90:
                health_status = 'critical'
                issues.append(f"Low disk space: {latest_metrics['disk_percent']:.1f}% used")
        
        # Check for recent alerts
        recent_alerts = [
            alert for alert in performance_monitor.performance_alerts
            if alert['timestamp'] >= (timezone.now() - timedelta(minutes=5)).isoformat()
        ]
        
        if recent_alerts and health_status == 'healthy':
            health_status = 'warning'
        
        return JsonResponse({
            'status': health_status,
            'timestamp': timezone.now().isoformat(),
            'system_metrics': latest_metrics,
            'issues': issues,
            'recent_alerts': len(recent_alerts),
            'uptime_info': {
                'total_queries': performance_monitor.total_queries,
                'total_api_calls': performance_monitor.total_api_calls,
                'slow_query_rate': (performance_monitor.slow_queries / performance_monitor.total_queries * 100) if performance_monitor.total_queries > 0 else 0
            }
        })
        
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'timestamp': timezone.now().isoformat(),
            'error': 'Health check failed'
        }, status=500)