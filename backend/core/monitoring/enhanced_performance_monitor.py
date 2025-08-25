"""
Enhanced Performance Monitor - Task 6.2.2

Advanced performance monitoring with real-time analytics, alerting, 
and comprehensive application performance monitoring (APM) capabilities.
"""

import os
import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from statistics import mean, median, stdev
import json

from django.core.cache import cache
from django.utils import timezone
from django.db import connection
from django.conf import settings
from django.dispatch import Signal

# Import existing monitor
from .performance_monitor import PerformanceMonitor

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Performance monitoring signals
performance_threshold_exceeded = Signal()
performance_regression_detected = Signal()
system_health_critical = Signal()

logger = logging.getLogger('enhanced_performance')


@dataclass
class PerformanceThreshold:
    """Performance threshold configuration"""
    metric_name: str
    warning_threshold: float
    critical_threshold: float
    comparison: str = 'greater'  # 'greater', 'less', 'equal'
    consecutive_violations: int = 3
    cooldown_minutes: int = 15
    enabled: bool = True


@dataclass
class PerformanceAlert:
    """Performance alert data"""
    alert_id: str
    metric_name: str
    severity: str  # 'warning', 'critical'
    current_value: float
    threshold_value: float
    message: str
    timestamp: datetime
    endpoint: Optional[str] = None
    organization_id: Optional[int] = None
    user_id: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceTrend:
    """Performance trend analysis"""
    metric_name: str
    timeframe: str
    current_avg: float
    previous_avg: float
    change_percent: float
    trend_direction: str  # 'improving', 'degrading', 'stable'
    confidence: float  # 0.0 to 1.0
    data_points: int


@dataclass
class ApplicationMetrics:
    """Application-level performance metrics"""
    timestamp: datetime
    active_users: int
    active_sessions: int
    cache_hit_rate: float
    database_pool_usage: float
    queue_size: int
    error_rate: float
    memory_usage_mb: float
    cpu_usage_percent: float
    response_time_p95: float
    throughput_rps: float


class EnhancedPerformanceMonitor(PerformanceMonitor):
    """
    Enhanced performance monitoring with advanced analytics and alerting
    Task 6.2.2: Comprehensive performance monitoring enhancements
    """
    
    def __init__(self):
        super().__init__()
        
        # Enhanced monitoring configuration
        self.monitoring_enabled = True
        self.alert_enabled = True
        self.trend_analysis_enabled = True
        
        # Performance thresholds
        self.thresholds = self._initialize_default_thresholds()
        
        # Enhanced data structures
        self.application_metrics = deque(maxlen=2880)  # 48 hours of minute data
        self.performance_trends = {}
        self.active_alerts = {}
        self.alert_history = deque(maxlen=10000)
        
        # Threshold violation tracking
        self.threshold_violations = defaultdict(list)
        
        # Performance regression detection
        self.baseline_metrics = {}
        self.regression_sensitivity = 0.15  # 15% threshold for regression
        
        # Real-time monitoring
        self.real_time_subscribers = []
        self.monitoring_interval = 60  # seconds
        
        # Start enhanced monitoring
        self._start_enhanced_monitoring()
        
        logger.info("Enhanced Performance Monitor initialized")
    
    def _initialize_default_thresholds(self) -> Dict[str, PerformanceThreshold]:
        """Initialize default performance thresholds"""
        return {
            'api_response_time_p95': PerformanceThreshold(
                metric_name='api_response_time_p95',
                warning_threshold=2.0,
                critical_threshold=5.0,
                comparison='greater'
            ),
            'database_query_time_avg': PerformanceThreshold(
                metric_name='database_query_time_avg',
                warning_threshold=0.5,
                critical_threshold=2.0,
                comparison='greater'
            ),
            'error_rate_percent': PerformanceThreshold(
                metric_name='error_rate_percent',
                warning_threshold=5.0,
                critical_threshold=10.0,
                comparison='greater'
            ),
            'memory_usage_percent': PerformanceThreshold(
                metric_name='memory_usage_percent',
                warning_threshold=80.0,
                critical_threshold=90.0,
                comparison='greater'
            ),
            'cpu_usage_percent': PerformanceThreshold(
                metric_name='cpu_usage_percent',
                warning_threshold=80.0,
                critical_threshold=95.0,
                comparison='greater'
            ),
            'cache_hit_rate': PerformanceThreshold(
                metric_name='cache_hit_rate',
                warning_threshold=70.0,
                critical_threshold=50.0,
                comparison='less'
            ),
            'database_pool_usage': PerformanceThreshold(
                metric_name='database_pool_usage',
                warning_threshold=80.0,
                critical_threshold=95.0,
                comparison='greater'
            ),
            'throughput_rps': PerformanceThreshold(
                metric_name='throughput_rps',
                warning_threshold=10.0,
                critical_threshold=5.0,
                comparison='less'
            )
        }
    
    def _start_enhanced_monitoring(self):
        """Start enhanced monitoring thread"""
        def enhanced_monitoring_loop():
            while self.monitoring_enabled:
                try:
                    self._collect_enhanced_metrics()
                    self._analyze_performance_trends()
                    self._check_performance_thresholds()
                    self._detect_performance_regressions()
                    
                    time.sleep(self.monitoring_interval)
                    
                except Exception as e:
                    logger.error(f"Enhanced monitoring error: {e}")
                    time.sleep(30)  # Wait longer on error
        
        monitor_thread = threading.Thread(
            target=enhanced_monitoring_loop,
            daemon=True,
            name='enhanced_performance_monitor'
        )
        monitor_thread.start()
        
        logger.info("Enhanced performance monitoring started")
    
    def _collect_enhanced_metrics(self):
        """Collect enhanced application metrics"""
        try:
            # Get basic system metrics
            if PSUTIL_AVAILABLE:
                memory = psutil.virtual_memory()
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_usage_mb = memory.used / 1024 / 1024
            else:
                memory_usage_mb = 0
                cpu_percent = 0
            
            # Calculate application-specific metrics
            active_users = self._get_active_users_count()
            active_sessions = self._get_active_sessions_count()
            cache_hit_rate = self._calculate_cache_hit_rate()
            database_pool_usage = self._get_database_pool_usage()
            queue_size = self._get_background_queue_size()
            error_rate = self._calculate_error_rate()
            response_time_p95 = self._calculate_response_time_p95()
            throughput_rps = self._calculate_current_throughput()
            
            # Create application metrics object
            app_metrics = ApplicationMetrics(
                timestamp=timezone.now(),
                active_users=active_users,
                active_sessions=active_sessions,
                cache_hit_rate=cache_hit_rate,
                database_pool_usage=database_pool_usage,
                queue_size=queue_size,
                error_rate=error_rate,
                memory_usage_mb=memory_usage_mb,
                cpu_usage_percent=cpu_percent,
                response_time_p95=response_time_p95,
                throughput_rps=throughput_rps
            )
            
            # Store metrics
            self.application_metrics.append(app_metrics)
            
            # Update cache for real-time access
            cache.set('current_app_metrics', asdict(app_metrics), timeout=120)
            
            # Notify real-time subscribers
            self._notify_real_time_subscribers(app_metrics)
            
        except Exception as e:
            logger.error(f"Failed to collect enhanced metrics: {e}")
    
    def _get_active_users_count(self) -> int:
        """Get count of currently active users"""
        try:
            # Count active sessions from last 15 minutes
            from django.contrib.sessions.models import Session
            cutoff = timezone.now() - timedelta(minutes=15)
            return Session.objects.filter(expire_date__gt=timezone.now()).count()
        except Exception:
            return 0
    
    def _get_active_sessions_count(self) -> int:
        """Get count of active user sessions"""
        try:
            from django.contrib.sessions.models import Session
            return Session.objects.filter(expire_date__gt=timezone.now()).count()
        except Exception:
            return 0
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate current cache hit rate"""
        try:
            # Get cache statistics if available
            cache_stats = cache.get('cache_statistics', {})
            hits = cache_stats.get('hits', 0)
            misses = cache_stats.get('misses', 0)
            total = hits + misses
            
            if total == 0:
                return 0.0
            
            return (hits / total) * 100.0
        except Exception:
            return 0.0
    
    def _get_database_pool_usage(self) -> float:
        """Get database connection pool usage percentage"""
        try:
            # Get connection pool info if available
            from django.db import connections
            db_connections = len(connections.all())
            max_connections = getattr(settings, 'DATABASE_MAX_CONNECTIONS', 100)
            return (db_connections / max_connections) * 100.0
        except Exception:
            return 0.0
    
    def _get_background_queue_size(self) -> int:
        """Get background task queue size"""
        try:
            # This would integrate with Celery or other task queue
            # For now, return a placeholder
            return 0
        except Exception:
            return 0
    
    def _calculate_error_rate(self) -> float:
        """Calculate current error rate percentage"""
        try:
            # Calculate error rate from recent API metrics
            recent_metrics = list(self.api_metrics)[-100:]  # Last 100 API calls
            if not recent_metrics:
                return 0.0
            
            error_count = sum(1 for m in recent_metrics if m.get('status_code', 200) >= 400)
            return (error_count / len(recent_metrics)) * 100.0
        except Exception:
            return 0.0
    
    def _calculate_response_time_p95(self) -> float:
        """Calculate 95th percentile response time"""
        try:
            recent_metrics = list(self.api_metrics)[-1000:]  # Last 1000 API calls
            if not recent_metrics:
                return 0.0
            
            response_times = [m.get('response_time', 0) for m in recent_metrics]
            response_times.sort()
            
            if len(response_times) == 0:
                return 0.0
            
            p95_index = int(len(response_times) * 0.95)
            return response_times[p95_index] if p95_index < len(response_times) else response_times[-1]
        except Exception:
            return 0.0
    
    def _calculate_current_throughput(self) -> float:
        """Calculate current throughput (requests per second)"""
        try:
            # Calculate from last minute of API metrics
            one_minute_ago = timezone.now() - timedelta(minutes=1)
            recent_metrics = [
                m for m in self.api_metrics 
                if m.get('timestamp') and 
                   datetime.fromisoformat(m['timestamp'].replace('Z', '+00:00')) > one_minute_ago
            ]
            
            return len(recent_metrics) / 60.0  # Convert to per second
        except Exception:
            return 0.0
    
    def _analyze_performance_trends(self):
        """Analyze performance trends over time"""
        if not self.trend_analysis_enabled or len(self.application_metrics) < 10:
            return
        
        try:
            # Analyze trends for key metrics
            metrics_to_analyze = [
                'response_time_p95', 'throughput_rps', 'error_rate', 
                'memory_usage_mb', 'cpu_usage_percent', 'cache_hit_rate'
            ]
            
            for metric_name in metrics_to_analyze:
                trend = self._calculate_metric_trend(metric_name)
                if trend:
                    self.performance_trends[metric_name] = trend
        
        except Exception as e:
            logger.error(f"Trend analysis error: {e}")
    
    def _calculate_metric_trend(self, metric_name: str) -> Optional[PerformanceTrend]:
        """Calculate trend for a specific metric"""
        try:
            # Get recent data points
            recent_data = list(self.application_metrics)[-60:]  # Last hour
            older_data = list(self.application_metrics)[-120:-60]  # Previous hour
            
            if len(recent_data) < 5 or len(older_data) < 5:
                return None
            
            # Calculate averages
            recent_values = [getattr(m, metric_name) for m in recent_data]
            older_values = [getattr(m, metric_name) for m in older_data]
            
            current_avg = mean(recent_values)
            previous_avg = mean(older_values)
            
            # Calculate change percentage
            if previous_avg == 0:
                change_percent = 0
            else:
                change_percent = ((current_avg - previous_avg) / previous_avg) * 100
            
            # Determine trend direction
            if abs(change_percent) < 5:  # 5% threshold for stability
                trend_direction = 'stable'
            elif change_percent > 0:
                # For error rates and response times, increase is degrading
                if metric_name in ['error_rate', 'response_time_p95', 'memory_usage_mb', 'cpu_usage_percent']:
                    trend_direction = 'degrading'
                else:
                    trend_direction = 'improving'
            else:
                # For error rates and response times, decrease is improving
                if metric_name in ['error_rate', 'response_time_p95', 'memory_usage_mb', 'cpu_usage_percent']:
                    trend_direction = 'improving'
                else:
                    trend_direction = 'degrading'
            
            # Calculate confidence based on data consistency
            try:
                recent_stdev = stdev(recent_values) if len(recent_values) > 1 else 0
                confidence = max(0.1, min(1.0, 1.0 - (recent_stdev / (current_avg + 1))))
            except:
                confidence = 0.5
            
            return PerformanceTrend(
                metric_name=metric_name,
                timeframe='1h',
                current_avg=current_avg,
                previous_avg=previous_avg,
                change_percent=change_percent,
                trend_direction=trend_direction,
                confidence=confidence,
                data_points=len(recent_data)
            )
            
        except Exception as e:
            logger.error(f"Error calculating trend for {metric_name}: {e}")
            return None
    
    def _check_performance_thresholds(self):
        """Check performance thresholds and generate alerts"""
        if not self.alert_enabled or not self.application_metrics:
            return
        
        try:
            current_metrics = self.application_metrics[-1]
            
            for threshold_name, threshold in self.thresholds.items():
                if not threshold.enabled:
                    continue
                
                # Get current metric value
                metric_value = getattr(current_metrics, threshold.metric_name, None)
                if metric_value is None:
                    continue
                
                # Check threshold violation
                violation = self._check_threshold_violation(metric_value, threshold)
                
                if violation:
                    self._handle_threshold_violation(threshold, metric_value, current_metrics)
                else:
                    self._clear_threshold_violation(threshold.metric_name)
        
        except Exception as e:
            logger.error(f"Threshold checking error: {e}")
    
    def _check_threshold_violation(self, value: float, threshold: PerformanceThreshold) -> bool:
        """Check if a threshold is violated"""
        if threshold.comparison == 'greater':
            return value > threshold.warning_threshold
        elif threshold.comparison == 'less':
            return value < threshold.warning_threshold
        elif threshold.comparison == 'equal':
            return abs(value - threshold.warning_threshold) < 0.001
        return False
    
    def _handle_threshold_violation(self, threshold: PerformanceThreshold, 
                                   current_value: float, metrics: ApplicationMetrics):
        """Handle threshold violation"""
        violation_key = threshold.metric_name
        violation_time = timezone.now()
        
        # Track consecutive violations
        self.threshold_violations[violation_key].append(violation_time)
        
        # Clean old violations outside cooldown period
        cooldown_cutoff = violation_time - timedelta(minutes=threshold.cooldown_minutes)
        self.threshold_violations[violation_key] = [
            v for v in self.threshold_violations[violation_key] 
            if v > cooldown_cutoff
        ]
        
        # Check if we have enough consecutive violations
        if len(self.threshold_violations[violation_key]) >= threshold.consecutive_violations:
            # Determine severity
            severity = 'critical' if current_value > threshold.critical_threshold else 'warning'
            
            # Generate alert
            alert = PerformanceAlert(
                alert_id=f"{violation_key}_{int(violation_time.timestamp())}",
                metric_name=threshold.metric_name,
                severity=severity,
                current_value=current_value,
                threshold_value=threshold.warning_threshold if severity == 'warning' else threshold.critical_threshold,
                message=f"{threshold.metric_name} exceeded {severity} threshold: {current_value:.2f}",
                timestamp=violation_time,
                metadata={
                    'consecutive_violations': len(self.threshold_violations[violation_key]),
                    'threshold_config': asdict(threshold)
                }
            )
            
            # Store alert
            self.active_alerts[alert.alert_id] = alert
            self.alert_history.append(alert)
            
            # Send notifications
            self._send_performance_alert(alert)
            
            # Reset violation count after alert
            self.threshold_violations[violation_key] = []
    
    def _clear_threshold_violation(self, metric_name: str):
        """Clear threshold violations for a metric"""
        if metric_name in self.threshold_violations:
            del self.threshold_violations[metric_name]
        
        # Clear related active alerts
        alerts_to_clear = [
            alert_id for alert_id, alert in self.active_alerts.items()
            if alert.metric_name == metric_name
        ]
        
        for alert_id in alerts_to_clear:
            del self.active_alerts[alert_id]
    
    def _detect_performance_regressions(self):
        """Detect performance regressions against baselines"""
        if not self.application_metrics or not self.baseline_metrics:
            return
        
        try:
            current_metrics = self.application_metrics[-1]
            
            for metric_name, baseline_value in self.baseline_metrics.items():
                current_value = getattr(current_metrics, metric_name, None)
                if current_value is None:
                    continue
                
                # Calculate regression percentage
                if baseline_value == 0:
                    continue
                
                change_percent = ((current_value - baseline_value) / baseline_value) * 100
                
                # Check for regression (performance degradation)
                is_regression = False
                if metric_name in ['response_time_p95', 'error_rate', 'memory_usage_mb', 'cpu_usage_percent']:
                    # For these metrics, increase is bad
                    is_regression = change_percent > (self.regression_sensitivity * 100)
                else:
                    # For metrics like throughput and cache hit rate, decrease is bad
                    is_regression = change_percent < -(self.regression_sensitivity * 100)
                
                if is_regression:
                    self._handle_performance_regression(
                        metric_name, current_value, baseline_value, change_percent
                    )
        
        except Exception as e:
            logger.error(f"Regression detection error: {e}")
    
    def _handle_performance_regression(self, metric_name: str, current_value: float,
                                     baseline_value: float, change_percent: float):
        """Handle detected performance regression"""
        # Send regression signal
        performance_regression_detected.send(
            sender=self.__class__,
            metric_name=metric_name,
            current_value=current_value,
            baseline_value=baseline_value,
            change_percent=change_percent
        )
        
        logger.warning(
            f"Performance regression detected: {metric_name} changed by {change_percent:.1f}% "
            f"({baseline_value:.3f} → {current_value:.3f})"
        )
    
    def _send_performance_alert(self, alert: PerformanceAlert):
        """Send performance alert notifications"""
        # Send threshold exceeded signal
        performance_threshold_exceeded.send(
            sender=self.__class__,
            alert=alert
        )
        
        # Log alert
        logger.warning(f"Performance alert: {alert.message}")
        
        # Send system health critical signal for critical alerts
        if alert.severity == 'critical':
            system_health_critical.send(
                sender=self.__class__,
                alert=alert
            )
    
    def _notify_real_time_subscribers(self, metrics: ApplicationMetrics):
        """Notify real-time monitoring subscribers"""
        for subscriber in self.real_time_subscribers:
            try:
                subscriber(metrics)
            except Exception as e:
                logger.error(f"Real-time subscriber notification error: {e}")
    
    def establish_performance_baseline(self, duration_minutes: int = 60):
        """Establish performance baseline from current metrics"""
        if len(self.application_metrics) < duration_minutes:
            raise ValueError(f"Need at least {duration_minutes} minutes of data to establish baseline")
        
        # Get recent metrics for baseline
        recent_metrics = list(self.application_metrics)[-duration_minutes:]
        
        # Calculate baseline values
        baseline = {}
        metric_names = [
            'response_time_p95', 'throughput_rps', 'error_rate',
            'memory_usage_mb', 'cpu_usage_percent', 'cache_hit_rate'
        ]
        
        for metric_name in metric_names:
            values = [getattr(m, metric_name) for m in recent_metrics]
            baseline[metric_name] = mean(values)
        
        self.baseline_metrics = baseline
        
        # Save baseline to cache
        cache.set('performance_baseline', baseline, timeout=86400 * 7)  # 1 week
        
        logger.info(f"Performance baseline established with {duration_minutes} minutes of data")
        return baseline
    
    def subscribe_real_time_updates(self, callback: Callable):
        """Subscribe to real-time performance updates"""
        self.real_time_subscribers.append(callback)
    
    def unsubscribe_real_time_updates(self, callback: Callable):
        """Unsubscribe from real-time performance updates"""
        if callback in self.real_time_subscribers:
            self.real_time_subscribers.remove(callback)
    
    def get_performance_dashboard_data(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive dashboard data"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        
        # Get recent metrics
        recent_metrics = [
            m for m in self.application_metrics 
            if m.timestamp > cutoff_time
        ]
        
        if not recent_metrics:
            return {}
        
        # Calculate summary statistics
        summary = {
            'timeframe_hours': hours,
            'data_points': len(recent_metrics),
            'last_updated': recent_metrics[-1].timestamp.isoformat() if recent_metrics else None,
            'current_metrics': asdict(recent_metrics[-1]) if recent_metrics else {},
            'averages': {},
            'trends': {name: asdict(trend) for name, trend in self.performance_trends.items()},
            'active_alerts': [asdict(alert) for alert in self.active_alerts.values()],
            'alert_history': [asdict(alert) for alert in list(self.alert_history)[-50:]],
            'thresholds': {name: asdict(threshold) for name, threshold in self.thresholds.items()},
            'baseline_metrics': self.baseline_metrics.copy()
        }
        
        # Calculate averages for dashboard
        metric_names = [
            'active_users', 'response_time_p95', 'throughput_rps', 'error_rate',
            'memory_usage_mb', 'cpu_usage_percent', 'cache_hit_rate'
        ]
        
        for metric_name in metric_names:
            values = [getattr(m, metric_name) for m in recent_metrics]
            if values:
                summary['averages'][metric_name] = {
                    'mean': mean(values),
                    'min': min(values),
                    'max': max(values),
                    'current': values[-1]
                }
        
        return summary
    
    def update_threshold(self, metric_name: str, **kwargs):
        """Update performance threshold configuration"""
        if metric_name in self.thresholds:
            threshold = self.thresholds[metric_name]
            for key, value in kwargs.items():
                if hasattr(threshold, key):
                    setattr(threshold, key, value)
            
            logger.info(f"Updated threshold for {metric_name}: {kwargs}")
        else:
            logger.error(f"Unknown threshold metric: {metric_name}")
    
    def get_metric_history(self, metric_name: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get historical data for a specific metric"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        
        return [
            {
                'timestamp': m.timestamp.isoformat(),
                'value': getattr(m, metric_name)
            }
            for m in self.application_metrics
            if m.timestamp > cutoff_time and hasattr(m, metric_name)
        ]


# Global enhanced monitor instance
enhanced_performance_monitor = EnhancedPerformanceMonitor()
