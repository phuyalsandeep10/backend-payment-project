"""
Performance Monitor
Implements comprehensive performance monitoring for database queries, API response times, and system metrics
"""

from django.core.cache import cache
from django.utils import timezone
from django.db import connection
from django.conf import settings
from datetime import timedelta, datetime
from typing import Dict, List, Optional, Any
import time
import logging
import threading
from collections import defaultdict, deque
from functools import wraps

# Performance logger
performance_logger = logging.getLogger('performance')

class PerformanceMonitor:
    """
    Comprehensive performance monitoring system
    """
    
    # Singleton instance
    _instance = None
    _lock = threading.Lock()
    
    # Monitoring configuration
    METRICS_RETENTION_HOURS = 24
    SLOW_QUERY_THRESHOLD = 1.0  # seconds
    SLOW_API_THRESHOLD = 2.0  # seconds
    MEMORY_WARNING_THRESHOLD = 80  # percent
    CPU_WARNING_THRESHOLD = 80  # percent
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize monitoring data structures"""
        self.query_metrics = deque(maxlen=10000)  # Last 10k queries
        self.api_metrics = deque(maxlen=10000)  # Last 10k API calls
        self.system_metrics = deque(maxlen=1440)  # 24 hours of minute-by-minute data
        self.error_metrics = defaultdict(int)
        self.performance_alerts = deque(maxlen=1000)  # Last 1k alerts
        
        # Performance counters
        self.total_queries = 0
        self.slow_queries = 0
        self.total_api_calls = 0
        self.slow_api_calls = 0
        
        # Start background monitoring
        self._start_system_monitoring()
    
    def _start_system_monitoring(self):
        """Start background system monitoring thread"""
        def monitor_system():
            while True:
                try:
                    self._collect_system_metrics()
                    time.sleep(60)  # Collect every minute
                except Exception as e:
                    performance_logger.error(f"System monitoring error: {str(e)}")
                    time.sleep(60)
        
        monitor_thread = threading.Thread(target=monitor_system, daemon=True)
        monitor_thread.start()
    
    def _collect_system_metrics(self):
        """Collect system performance metrics"""
        try:
            # Basic system metrics (simplified for compatibility)
            import os
            
            try:
                import psutil
                # CPU and memory metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                metrics = {
                    'timestamp': timezone.now().isoformat(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_available_mb': memory.available / (1024 * 1024),
                    'disk_percent': disk.percent,
                    'disk_free_gb': disk.free / (1024 * 1024 * 1024),
                    'db_connections': len(connection.queries),
                    'total_queries': self.total_queries,
                    'slow_queries': self.slow_queries,
                    'total_api_calls': self.total_api_calls,
                    'slow_api_calls': self.slow_api_calls
                }
            except ImportError:
                # Fallback metrics without psutil
                metrics = {
                    'timestamp': timezone.now().isoformat(),
                    'cpu_percent': 0,
                    'memory_percent': 0,
                    'memory_available_mb': 0,
                    'disk_percent': 0,
                    'disk_free_gb': 0,
                    'db_connections': len(connection.queries),
                    'total_queries': self.total_queries,
                    'slow_queries': self.slow_queries,
                    'total_api_calls': self.total_api_calls,
                    'slow_api_calls': self.slow_api_calls
                }
            
            self.system_metrics.append(metrics)
            
        except Exception as e:
            performance_logger.error(f"Failed to collect system metrics: {str(e)}")
    
    def record_query_performance(self, query: str, execution_time: float, 
                               organization_id: Optional[int] = None):
        """Record database query performance"""
        self.total_queries += 1
        
        if execution_time > self.SLOW_QUERY_THRESHOLD:
            self.slow_queries += 1
        
        query_metric = {
            'timestamp': timezone.now().isoformat(),
            'query': query[:500],  # Truncate long queries
            'execution_time': execution_time,
            'organization_id': organization_id,
            'is_slow': execution_time > self.SLOW_QUERY_THRESHOLD
        }
        
        self.query_metrics.append(query_metric)
        
        # Log slow queries
        if execution_time > self.SLOW_QUERY_THRESHOLD:
            performance_logger.warning(
                f"Slow query detected: {execution_time:.3f}s - {query[:200]}..."
            )
    
    def record_api_performance(self, endpoint: str, method: str, response_time: float,
                             status_code: int, organization_id: Optional[int] = None,
                             user_id: Optional[int] = None):
        """Record API endpoint performance"""
        self.total_api_calls += 1
        
        if response_time > self.SLOW_API_THRESHOLD:
            self.slow_api_calls += 1
        
        api_metric = {
            'timestamp': timezone.now().isoformat(),
            'endpoint': endpoint,
            'method': method,
            'response_time': response_time,
            'status_code': status_code,
            'organization_id': organization_id,
            'user_id': user_id,
            'is_slow': response_time > self.SLOW_API_THRESHOLD
        }
        
        self.api_metrics.append(api_metric)
        
        # Log slow API calls
        if response_time > self.SLOW_API_THRESHOLD:
            performance_logger.warning(
                f"Slow API call: {method} {endpoint} - {response_time:.3f}s"
            )
        
        # Track error rates
        if status_code >= 400:
            error_key = f"{method}_{endpoint}_{status_code}"
            self.error_metrics[error_key] += 1
    
    def get_performance_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get performance summary for the specified time period"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        cutoff_str = cutoff_time.isoformat()
        
        # Filter metrics by time
        recent_queries = [q for q in self.query_metrics if q['timestamp'] >= cutoff_str]
        recent_api_calls = [a for a in self.api_metrics if a['timestamp'] >= cutoff_str]
        recent_system_metrics = [s for s in self.system_metrics if s['timestamp'] >= cutoff_str]
        
        # Calculate query statistics
        query_stats = self._calculate_query_stats(recent_queries)
        
        # Calculate API statistics
        api_stats = self._calculate_api_stats(recent_api_calls)
        
        # Get latest system metrics
        latest_system = recent_system_metrics[-1] if recent_system_metrics else {}
        
        # Get recent alerts
        recent_alerts = [a for a in self.performance_alerts if a['timestamp'] >= cutoff_str]
        
        return {
            'period_hours': hours,
            'generated_at': timezone.now().isoformat(),
            'query_performance': query_stats,
            'api_performance': api_stats,
            'system_metrics': latest_system,
            'alerts': recent_alerts,
            'summary': {
                'total_queries': len(recent_queries),
                'slow_queries': len([q for q in recent_queries if q['is_slow']]),
                'total_api_calls': len(recent_api_calls),
                'slow_api_calls': len([a for a in recent_api_calls if a['is_slow']]),
                'alerts_count': len(recent_alerts)
            }
        }
    
    def _calculate_query_stats(self, queries: List[Dict]) -> Dict[str, Any]:
        """Calculate query performance statistics"""
        if not queries:
            return {'total': 0, 'avg_time': 0, 'slow_queries': 0}
        
        execution_times = [q['execution_time'] for q in queries]
        slow_queries = [q for q in queries if q['is_slow']]
        
        return {
            'total': len(queries),
            'avg_time': sum(execution_times) / len(execution_times),
            'min_time': min(execution_times),
            'max_time': max(execution_times),
            'slow_queries': len(slow_queries),
            'slow_query_rate': (len(slow_queries) / len(queries)) * 100
        }
    
    def _calculate_api_stats(self, api_calls: List[Dict]) -> Dict[str, Any]:
        """Calculate API performance statistics"""
        if not api_calls:
            return {'total': 0, 'avg_time': 0, 'slow_calls': 0}
        
        response_times = [a['response_time'] for a in api_calls]
        slow_calls = [a for a in api_calls if a['is_slow']]
        
        return {
            'total': len(api_calls),
            'avg_time': sum(response_times) / len(response_times),
            'min_time': min(response_times),
            'max_time': max(response_times),
            'slow_calls': len(slow_calls),
            'slow_call_rate': (len(slow_calls) / len(api_calls)) * 100,
            'error_rate': sum(1 for call in api_calls if call['status_code'] >= 400) / len(api_calls) * 100
        }
    
    def get_slow_queries(self, limit: int = 50) -> List[Dict]:
        """Get slowest queries"""
        slow_queries = [q for q in self.query_metrics if q['is_slow']]
        return sorted(slow_queries, key=lambda x: x['execution_time'], reverse=True)[:limit]
    
    def get_slow_api_calls(self, limit: int = 50) -> List[Dict]:
        """Get slowest API calls"""
        slow_calls = [a for a in self.api_metrics if a['is_slow']]
        return sorted(slow_calls, key=lambda x: x['response_time'], reverse=True)[:limit]
    
    def get_performance_trends(self, hours: int = 24) -> Dict[str, Any]:
        """Get performance trends over time"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        cutoff_str = cutoff_time.isoformat()
        
        recent_system_metrics = [s for s in self.system_metrics if s['timestamp'] >= cutoff_str]
        
        if not recent_system_metrics:
            return {'error': 'No data available for the specified period'}
        
        # Extract time series data
        timestamps = [m['timestamp'] for m in recent_system_metrics]
        cpu_data = [m['cpu_percent'] for m in recent_system_metrics]
        memory_data = [m['memory_percent'] for m in recent_system_metrics]
        
        return {
            'period_hours': hours,
            'data_points': len(recent_system_metrics),
            'time_series': {
                'timestamps': timestamps,
                'cpu_percent': cpu_data,
                'memory_percent': memory_data
            },
            'trends': {
                'cpu_avg': sum(cpu_data) / len(cpu_data),
                'cpu_max': max(cpu_data),
                'memory_avg': sum(memory_data) / len(memory_data),
                'memory_max': max(memory_data)
            }
        }
    
    def clear_old_metrics(self):
        """Clear old metrics to prevent memory buildup"""
        cutoff_time = timezone.now() - timedelta(hours=self.METRICS_RETENTION_HOURS)
        cutoff_str = cutoff_time.isoformat()
        
        # Clear old query metrics
        self.query_metrics = deque(
            [q for q in self.query_metrics if q['timestamp'] >= cutoff_str],
            maxlen=10000
        )
        
        # Clear old API metrics
        self.api_metrics = deque(
            [a for a in self.api_metrics if a['timestamp'] >= cutoff_str],
            maxlen=10000
        )
        
        # Clear old alerts
        self.performance_alerts = deque(
            [a for a in self.performance_alerts if a['timestamp'] >= cutoff_str],
            maxlen=1000
        )
        
        performance_logger.info("Cleared old performance metrics")


# Middleware for automatic API monitoring
class PerformanceMonitoringMiddleware:
    """Middleware to automatically monitor API performance"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.monitor = PerformanceMonitor()
    
    def __call__(self, request):
        start_time = time.time()
        
        response = self.get_response(request)
        
        response_time = time.time() - start_time
        
        # Only monitor API endpoints
        if request.path.startswith('/api/'):
            # Extract information
            endpoint = request.path
            method = request.method
            status_code = getattr(response, 'status_code', 200)
            
            # Try to get organization and user info
            organization_id = None
            user_id = None
            
            if hasattr(request, 'user') and request.user.is_authenticated:
                user_id = request.user.id
                if hasattr(request.user, 'organization') and request.user.organization is not None:
                    organization_id = request.user.organization.id
            
            self.monitor.record_api_performance(
                endpoint=endpoint,
                method=method,
                response_time=response_time,
                status_code=status_code,
                organization_id=organization_id,
                user_id=user_id
            )
        
        return response


# Global performance monitor instance
performance_monitor = PerformanceMonitor()