"""
Cache Performance Monitor - Task 4.1.1

Comprehensive cache performance monitoring system to establish baselines
and track cache effectiveness across all application layers.
"""

import time
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from django.db import models
import json

logger = logging.getLogger(__name__)


@dataclass
class CacheMetric:
    """Individual cache operation metric"""
    operation: str  # 'get', 'set', 'delete', 'clear'
    key: str
    hit: bool
    execution_time: float
    data_size: int  # Size in bytes
    timestamp: datetime
    cache_backend: str
    ttl: Optional[int] = None
    

@dataclass 
class CacheStats:
    """Aggregated cache statistics"""
    total_operations: int = 0
    hit_count: int = 0
    miss_count: int = 0
    hit_rate: float = 0.0
    avg_response_time: float = 0.0
    total_data_transferred: int = 0
    operations_per_second: float = 0.0
    cache_backend: str = ""
    timeframe_start: datetime = field(default_factory=timezone.now)
    timeframe_end: datetime = field(default_factory=timezone.now)


class CachePerformanceCollector:
    """
    Real-time cache performance metrics collector
    Task 4.1.1: Core metrics collection system
    """
    
    def __init__(self, max_metrics_history: int = 10000):
        self.metrics_history = deque(maxlen=max_metrics_history)
        self.stats_cache = {}
        self.lock = threading.Lock()
        self._active = True
        
        # Performance thresholds (configurable)
        self.slow_operation_threshold = 0.05  # 50ms
        self.low_hit_rate_threshold = 0.7     # 70%
        self.high_memory_threshold = 100 * 1024 * 1024  # 100MB
        
    def record_cache_operation(
        self, 
        operation: str, 
        key: str, 
        hit: bool, 
        execution_time: float,
        data_size: int = 0,
        ttl: Optional[int] = None,
        cache_backend: str = 'default'
    ):
        """Record a cache operation for performance analysis"""
        
        if not self._active:
            return
            
        try:
            metric = CacheMetric(
                operation=operation,
                key=key,
                hit=hit,
                execution_time=execution_time,
                data_size=data_size,
                timestamp=timezone.now(),
                cache_backend=cache_backend,
                ttl=ttl
            )
            
            with self.lock:
                self.metrics_history.append(metric)
                
            # Alert on performance issues
            self._check_performance_alerts(metric)
            
        except Exception as e:
            logger.error(f"Error recording cache metric: {e}")
    
    def get_baseline_stats(self, timeframe_minutes: int = 60) -> CacheStats:
        """
        Calculate baseline cache performance statistics
        Task 4.1.1: Establish performance baselines
        """
        
        cutoff_time = timezone.now() - timedelta(minutes=timeframe_minutes)
        
        with self.lock:
            relevant_metrics = [
                m for m in self.metrics_history 
                if m.timestamp >= cutoff_time
            ]
        
        if not relevant_metrics:
            return CacheStats()
        
        # Calculate statistics
        total_ops = len(relevant_metrics)
        hits = sum(1 for m in relevant_metrics if m.hit)
        misses = total_ops - hits
        hit_rate = hits / total_ops if total_ops > 0 else 0.0
        
        avg_response_time = sum(m.execution_time for m in relevant_metrics) / total_ops
        total_data = sum(m.data_size for m in relevant_metrics)
        
        # Operations per second
        time_span = (relevant_metrics[-1].timestamp - relevant_metrics[0].timestamp).total_seconds()
        ops_per_second = total_ops / time_span if time_span > 0 else 0.0
        
        return CacheStats(
            total_operations=total_ops,
            hit_count=hits,
            miss_count=misses,
            hit_rate=hit_rate,
            avg_response_time=avg_response_time,
            total_data_transferred=total_data,
            operations_per_second=ops_per_second,
            cache_backend='default',
            timeframe_start=relevant_metrics[0].timestamp if relevant_metrics else timezone.now(),
            timeframe_end=relevant_metrics[-1].timestamp if relevant_metrics else timezone.now()
        )
    
    def get_performance_trends(self, hours: int = 24) -> Dict[str, List[float]]:
        """
        Get performance trends over time
        Task 4.1.1: Trend analysis for baselines
        """
        
        cutoff_time = timezone.now() - timedelta(hours=hours)
        
        with self.lock:
            relevant_metrics = [
                m for m in self.metrics_history 
                if m.timestamp >= cutoff_time
            ]
        
        # Group by hour
        hourly_stats = defaultdict(list)
        
        for metric in relevant_metrics:
            hour_key = metric.timestamp.strftime('%H')
            hourly_stats[hour_key].append(metric)
        
        trends = {
            'hit_rates': [],
            'response_times': [],
            'operations_count': [],
            'data_volumes': [],
            'hours': []
        }
        
        for hour in sorted(hourly_stats.keys()):
            hour_metrics = hourly_stats[hour]
            
            hits = sum(1 for m in hour_metrics if m.hit)
            hit_rate = hits / len(hour_metrics) if hour_metrics else 0
            avg_response_time = sum(m.execution_time for m in hour_metrics) / len(hour_metrics) if hour_metrics else 0
            total_data = sum(m.data_size for m in hour_metrics)
            
            trends['hit_rates'].append(hit_rate)
            trends['response_times'].append(avg_response_time)
            trends['operations_count'].append(len(hour_metrics))
            trends['data_volumes'].append(total_data)
            trends['hours'].append(f"{hour}:00")
        
        return trends
    
    def get_slow_operations(self, limit: int = 20) -> List[CacheMetric]:
        """Get slowest cache operations for analysis"""
        
        with self.lock:
            slow_ops = [
                m for m in self.metrics_history 
                if m.execution_time > self.slow_operation_threshold
            ]
        
        # Sort by execution time descending
        slow_ops.sort(key=lambda m: m.execution_time, reverse=True)
        return slow_ops[:limit]
    
    def get_cache_key_analytics(self) -> Dict[str, Dict[str, Any]]:
        """
        Analyze cache key patterns and performance
        Task 4.1.1: Key-level performance analysis
        """
        
        key_stats = defaultdict(lambda: {
            'hit_count': 0,
            'miss_count': 0,
            'total_time': 0.0,
            'avg_time': 0.0,
            'data_size': 0,
            'last_accessed': None
        })
        
        with self.lock:
            for metric in self.metrics_history:
                key_pattern = self._extract_key_pattern(metric.key)
                stats = key_stats[key_pattern]
                
                if metric.hit:
                    stats['hit_count'] += 1
                else:
                    stats['miss_count'] += 1
                
                stats['total_time'] += metric.execution_time
                stats['data_size'] += metric.data_size
                stats['last_accessed'] = metric.timestamp
        
        # Calculate averages and hit rates
        for pattern, stats in key_stats.items():
            total_ops = stats['hit_count'] + stats['miss_count']
            if total_ops > 0:
                stats['hit_rate'] = stats['hit_count'] / total_ops
                stats['avg_time'] = stats['total_time'] / total_ops
            else:
                stats['hit_rate'] = 0.0
                stats['avg_time'] = 0.0
        
        return dict(key_stats)
    
    def _extract_key_pattern(self, key: str) -> str:
        """Extract pattern from cache key for grouping"""
        # Simple pattern extraction - replace IDs with wildcards
        import re
        
        # Replace UUIDs
        pattern = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '*', key)
        # Replace numeric IDs
        pattern = re.sub(r'\d+', '*', pattern)
        
        return pattern
    
    def _check_performance_alerts(self, metric: CacheMetric):
        """Check for performance alerts and log warnings"""
        
        if metric.execution_time > self.slow_operation_threshold:
            logger.warning(
                f"Slow cache operation detected: {metric.operation} on {metric.key} "
                f"took {metric.execution_time:.3f}s"
            )
        
        if metric.data_size > self.high_memory_threshold:
            logger.warning(
                f"Large cache data detected: {metric.key} is {metric.data_size / 1024 / 1024:.2f}MB"
            )
    
    def export_baseline_report(self, filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Export comprehensive baseline performance report
        Task 4.1.1: Baseline establishment and reporting
        """
        
        report = {
            'timestamp': timezone.now().isoformat(),
            'system_info': self._get_system_info(),
            'baseline_stats': self._serialize_stats(self.get_baseline_stats()),
            'performance_trends': self.get_performance_trends(),
            'slow_operations': [self._serialize_metric(m) for m in self.get_slow_operations()],
            'key_analytics': self.get_cache_key_analytics(),
            'recommendations': self._generate_recommendations()
        }
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                logger.info(f"Cache baseline report exported to {filename}")
            except Exception as e:
                logger.error(f"Error exporting baseline report: {e}")
        
        return report
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for baseline context"""
        return {
            'django_version': getattr(settings, 'DJANGO_VERSION', 'unknown'),
            'cache_backends': list(getattr(settings, 'CACHES', {}).keys()),
            'debug_mode': getattr(settings, 'DEBUG', False),
            'total_metrics_collected': len(self.metrics_history)
        }
    
    def _serialize_stats(self, stats: CacheStats) -> Dict[str, Any]:
        """Serialize CacheStats to dictionary"""
        return {
            'total_operations': stats.total_operations,
            'hit_count': stats.hit_count,
            'miss_count': stats.miss_count,
            'hit_rate': stats.hit_rate,
            'avg_response_time': stats.avg_response_time,
            'total_data_transferred': stats.total_data_transferred,
            'operations_per_second': stats.operations_per_second,
            'cache_backend': stats.cache_backend,
            'timeframe_start': stats.timeframe_start.isoformat() if stats.timeframe_start else None,
            'timeframe_end': stats.timeframe_end.isoformat() if stats.timeframe_end else None
        }
    
    def _serialize_metric(self, metric: CacheMetric) -> Dict[str, Any]:
        """Serialize CacheMetric to dictionary"""
        return {
            'operation': metric.operation,
            'key': metric.key,
            'hit': metric.hit,
            'execution_time': metric.execution_time,
            'data_size': metric.data_size,
            'timestamp': metric.timestamp.isoformat(),
            'cache_backend': metric.cache_backend,
            'ttl': metric.ttl
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance recommendations based on collected metrics"""
        recommendations = []
        
        baseline = self.get_baseline_stats()
        
        if baseline.hit_rate < self.low_hit_rate_threshold:
            recommendations.append(
                f"Cache hit rate is {baseline.hit_rate:.2%}, consider reviewing cache keys and TTL values"
            )
        
        if baseline.avg_response_time > self.slow_operation_threshold:
            recommendations.append(
                f"Average cache response time is {baseline.avg_response_time:.3f}s, consider cache backend optimization"
            )
        
        slow_ops = self.get_slow_operations(5)
        if slow_ops:
            recommendations.append(
                f"Found {len(slow_ops)} slow cache operations, review cache key patterns and data sizes"
            )
        
        key_analytics = self.get_cache_key_analytics()
        low_hit_keys = [k for k, stats in key_analytics.items() if stats['hit_rate'] < 0.5]
        if low_hit_keys:
            recommendations.append(
                f"Keys with low hit rates detected: {', '.join(low_hit_keys[:3])}, consider cache strategy review"
            )
        
        return recommendations
    
    def reset_metrics(self):
        """Reset all collected metrics"""
        with self.lock:
            self.metrics_history.clear()
            self.stats_cache.clear()
        
        logger.info("Cache performance metrics reset")


class CacheInstrumentation:
    """
    Cache instrumentation wrapper for automatic performance monitoring
    Task 4.1.1: Automatic metrics collection
    """
    
    def __init__(self, collector: CachePerformanceCollector):
        self.collector = collector
        self.original_cache_methods = {}
        self._instrumented = False
    
    def instrument_cache(self):
        """Instrument Django cache to automatically collect metrics"""
        
        if self._instrumented:
            return
        
        # Store original methods
        self.original_cache_methods = {
            'get': cache.get,
            'set': cache.set,
            'delete': cache.delete,
            'get_many': cache.get_many,
            'set_many': cache.set_many
        }
        
        # Replace with instrumented versions
        cache.get = self._instrument_get(cache.get)
        cache.set = self._instrument_set(cache.set)
        cache.delete = self._instrument_delete(cache.delete)
        cache.get_many = self._instrument_get_many(cache.get_many)
        cache.set_many = self._instrument_set_many(cache.set_many)
        
        self._instrumented = True
        logger.info("Cache instrumentation enabled")
    
    def _instrument_get(self, original_method):
        """Instrument cache.get method"""
        def instrumented_get(key, default=None, version=None):
            start_time = time.time()
            result = original_method(key, default, version)
            execution_time = time.time() - start_time
            
            hit = result is not default
            data_size = len(str(result)) if result else 0
            
            self.collector.record_cache_operation(
                operation='get',
                key=str(key),
                hit=hit,
                execution_time=execution_time,
                data_size=data_size
            )
            
            return result
        return instrumented_get
    
    def _instrument_set(self, original_method):
        """Instrument cache.set method"""
        def instrumented_set(key, value, timeout=None, version=None):
            start_time = time.time()
            result = original_method(key, value, timeout, version)
            execution_time = time.time() - start_time
            
            data_size = len(str(value)) if value else 0
            
            self.collector.record_cache_operation(
                operation='set',
                key=str(key),
                hit=True,  # Set operations are always successful
                execution_time=execution_time,
                data_size=data_size,
                ttl=timeout
            )
            
            return result
        return instrumented_set
    
    def _instrument_delete(self, original_method):
        """Instrument cache.delete method"""
        def instrumented_delete(key, version=None):
            start_time = time.time()
            result = original_method(key, version)
            execution_time = time.time() - start_time
            
            self.collector.record_cache_operation(
                operation='delete',
                key=str(key),
                hit=bool(result),
                execution_time=execution_time,
                data_size=0
            )
            
            return result
        return instrumented_delete
    
    def _instrument_get_many(self, original_method):
        """Instrument cache.get_many method"""
        def instrumented_get_many(keys, version=None):
            start_time = time.time()
            result = original_method(keys, version)
            execution_time = time.time() - start_time
            
            # Record metrics for each key
            for key in keys:
                hit = key in result
                data_size = len(str(result.get(key, ''))) if hit else 0
                
                self.collector.record_cache_operation(
                    operation='get_many',
                    key=str(key),
                    hit=hit,
                    execution_time=execution_time / len(keys),  # Distribute time
                    data_size=data_size
                )
            
            return result
        return instrumented_get_many
    
    def _instrument_set_many(self, original_method):
        """Instrument cache.set_many method"""
        def instrumented_set_many(data, timeout=None, version=None):
            start_time = time.time()
            result = original_method(data, timeout, version)
            execution_time = time.time() - start_time
            
            # Record metrics for each key
            for key, value in data.items():
                data_size = len(str(value)) if value else 0
                
                self.collector.record_cache_operation(
                    operation='set_many',
                    key=str(key),
                    hit=True,
                    execution_time=execution_time / len(data),  # Distribute time
                    data_size=data_size,
                    ttl=timeout
                )
            
            return result
        return instrumented_set_many
    
    def restore_cache(self):
        """Restore original cache methods"""
        if not self._instrumented:
            return
        
        for method_name, original_method in self.original_cache_methods.items():
            setattr(cache, method_name, original_method)
        
        self._instrumented = False
        logger.info("Cache instrumentation removed")


# Global cache performance collector instance
cache_performance_collector = CachePerformanceCollector()

# Global cache instrumentation
cache_instrumentation = CacheInstrumentation(cache_performance_collector)

# Auto-start instrumentation if in debug mode
if getattr(settings, 'DEBUG', False) or getattr(settings, 'CACHE_PERFORMANCE_MONITORING', False):
    cache_instrumentation.instrument_cache()
    logger.info("Cache performance monitoring started automatically")
