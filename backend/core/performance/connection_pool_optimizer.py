"""
Database Connection Pool Optimizer - Task 4.2.3

Optimizes database connection pool settings and implements connection health
monitoring for improved database performance and reliability.
"""

import logging
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from django.db import connection, connections
from django.conf import settings
from django.utils import timezone
import psutil
import json

logger = logging.getLogger(__name__)


@dataclass
class ConnectionMetrics:
    """Database connection metrics"""
    active_connections: int = 0
    idle_connections: int = 0
    total_connections: int = 0
    max_connections_used: int = 0
    connection_wait_time: float = 0.0
    avg_query_time: float = 0.0
    failed_connections: int = 0
    connection_errors: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=timezone.now)


@dataclass
class PoolConfiguration:
    """Connection pool configuration"""
    max_connections: int
    min_connections: int = 1
    connection_max_age: int = 3600  # 1 hour
    connection_timeout: int = 30
    pool_recycle: int = 7200  # 2 hours
    pool_pre_ping: bool = True
    health_check_interval: int = 300  # 5 minutes


class DatabaseConnectionMonitor:
    """
    Database connection monitoring and optimization system
    Task 4.2.3: Core connection monitoring functionality
    """
    
    def __init__(self, check_interval: int = 60):
        self.check_interval = check_interval
        self.metrics_history = deque(maxlen=1000)
        self.current_metrics = ConnectionMetrics()
        
        # Performance tracking
        self.connection_times = deque(maxlen=1000)
        self.query_times = deque(maxlen=1000)
        
        # Configuration tracking
        self.optimal_config = None
        self.config_history = []
        
        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread = None
        
        # System resources
        self.system_memory_gb = self._get_system_memory()
        self.cpu_cores = psutil.cpu_count()
        
        # Start monitoring
        self.start_monitoring()
    
    def start_monitoring(self):
        """Start connection pool monitoring"""
        
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        
        def monitoring_loop():
            while self.monitoring_active:
                try:
                    self._collect_connection_metrics()
                    time.sleep(self.check_interval)
                except Exception as e:
                    logger.error(f"Connection monitoring error: {e}")
                    time.sleep(30)  # Wait longer on error
        
        self.monitor_thread = threading.Thread(
            target=monitoring_loop, 
            daemon=True, 
            name='db_connection_monitor'
        )
        self.monitor_thread.start()
        
        logger.info("Database connection monitoring started")
    
    def stop_monitoring(self):
        """Stop connection pool monitoring"""
        
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        logger.info("Database connection monitoring stopped")
    
    def _collect_connection_metrics(self):
        """Collect current connection metrics"""
        
        try:
            # Get database connection stats
            with connection.cursor() as cursor:
                # PostgreSQL connection stats
                cursor.execute("""
                    SELECT 
                        count(*) as total_connections,
                        count(*) FILTER (WHERE state = 'active') as active_connections,
                        count(*) FILTER (WHERE state = 'idle') as idle_connections,
                        count(*) FILTER (WHERE state = 'idle in transaction') as idle_in_transaction
                    FROM pg_stat_activity 
                    WHERE datname = current_database()
                """)
                
                result = cursor.fetchone()
                if result:
                    total_conn, active_conn, idle_conn, idle_in_trans = result
                    
                    metrics = ConnectionMetrics(
                        total_connections=total_conn,
                        active_connections=active_conn,
                        idle_connections=idle_conn + idle_in_trans,
                        timestamp=timezone.now()
                    )
                    
                    # Update max connections used
                    if total_conn > self.current_metrics.max_connections_used:
                        metrics.max_connections_used = total_conn
                    else:
                        metrics.max_connections_used = self.current_metrics.max_connections_used
                    
                    # Calculate average times
                    if self.connection_times:
                        metrics.connection_wait_time = sum(self.connection_times) / len(self.connection_times)
                    
                    if self.query_times:
                        metrics.avg_query_time = sum(self.query_times) / len(self.query_times)
                    
                    self.current_metrics = metrics
                    self.metrics_history.append(metrics)
                    
                    # Check for issues
                    self._check_connection_health(metrics)
                    
        except Exception as e:
            logger.error(f"Error collecting connection metrics: {e}")
            self.current_metrics.connection_errors.append(str(e))
    
    def _check_connection_health(self, metrics: ConnectionMetrics):
        """Check connection pool health and log warnings"""
        
        # High connection usage warning
        max_conn_limit = self._get_max_connections_limit()
        if max_conn_limit and metrics.total_connections > max_conn_limit * 0.8:
            logger.warning(
                f"High database connection usage: {metrics.total_connections}/{max_conn_limit} "
                f"({(metrics.total_connections/max_conn_limit)*100:.1f}%)"
            )
        
        # Too many idle connections
        if metrics.idle_connections > 20 and metrics.idle_connections > metrics.active_connections * 2:
            logger.warning(
                f"High idle connection count: {metrics.idle_connections} idle vs "
                f"{metrics.active_connections} active"
            )
        
        # Slow connection times
        if metrics.connection_wait_time > 1.0:  # 1 second
            logger.warning(f"Slow database connections: {metrics.connection_wait_time:.3f}s average wait")
        
        # Slow query times
        if metrics.avg_query_time > 0.5:  # 500ms
            logger.warning(f"Slow query performance: {metrics.avg_query_time:.3f}s average query time")
    
    def record_connection_time(self, connection_time: float):
        """Record connection acquisition time"""
        self.connection_times.append(connection_time)
    
    def record_query_time(self, query_time: float):
        """Record query execution time"""
        self.query_times.append(query_time)
    
    def get_current_metrics(self) -> ConnectionMetrics:
        """Get current connection metrics"""
        return self.current_metrics
    
    def get_metrics_history(self, hours: int = 24) -> List[ConnectionMetrics]:
        """Get connection metrics history"""
        
        cutoff_time = timezone.now() - timedelta(hours=hours)
        
        return [
            metric for metric in self.metrics_history
            if metric.timestamp >= cutoff_time
        ]
    
    def _get_system_memory(self) -> float:
        """Get system memory in GB"""
        try:
            return psutil.virtual_memory().total / (1024**3)
        except:
            return 8.0  # Default assumption
    
    def _get_max_connections_limit(self) -> Optional[int]:
        """Get database max connections limit"""
        
        try:
            with connection.cursor() as cursor:
                cursor.execute("SHOW max_connections")
                result = cursor.fetchone()
                if result:
                    return int(result[0])
        except:
            pass
        
        return None


class ConnectionPoolOptimizer:
    """
    Connection pool optimization and configuration management
    Task 4.2.3: Connection pool optimization
    """
    
    def __init__(self, monitor: DatabaseConnectionMonitor):
        self.monitor = monitor
        self.current_config = self._get_current_config()
        self.optimization_rules = self._load_optimization_rules()
    
    def analyze_pool_performance(self) -> Dict[str, Any]:
        """
        Analyze connection pool performance and identify issues
        Task 4.2.3: Pool performance analysis
        """
        
        current_metrics = self.monitor.get_current_metrics()
        history_metrics = self.monitor.get_metrics_history(24)  # Last 24 hours
        
        if not history_metrics:
            return {
                'status': 'insufficient_data',
                'message': 'Not enough metrics collected for analysis'
            }
        
        # Calculate performance statistics
        avg_total_connections = sum(m.total_connections for m in history_metrics) / len(history_metrics)
        max_total_connections = max(m.total_connections for m in history_metrics)
        avg_active_connections = sum(m.active_connections for m in history_metrics) / len(history_metrics)
        avg_idle_connections = sum(m.idle_connections for m in history_metrics) / len(history_metrics)
        
        # Connection utilization
        max_conn_limit = self.monitor._get_max_connections_limit() or 100
        utilization_rate = (max_total_connections / max_conn_limit) * 100
        
        # Performance indicators
        avg_connection_wait = current_metrics.connection_wait_time
        avg_query_time = current_metrics.avg_query_time
        
        # Identify issues
        issues = []
        recommendations = []
        
        # High utilization
        if utilization_rate > 80:
            issues.append(f"High connection utilization: {utilization_rate:.1f}%")
            recommendations.append("Consider increasing max_connections or optimizing query performance")
        
        # Too many idle connections
        idle_ratio = avg_idle_connections / max(avg_total_connections, 1)
        if idle_ratio > 0.6:  # More than 60% idle
            issues.append(f"High idle connection ratio: {idle_ratio:.1%}")
            recommendations.append("Consider reducing connection pool size or implementing connection timeouts")
        
        # Slow connection acquisition
        if avg_connection_wait > 0.1:  # 100ms
            issues.append(f"Slow connection acquisition: {avg_connection_wait:.3f}s")
            recommendations.append("Consider increasing connection pool size")
        
        # Performance assessment
        if utilization_rate < 20 and idle_ratio > 0.8:
            performance_rating = "over_provisioned"
        elif utilization_rate > 80 or avg_connection_wait > 0.5:
            performance_rating = "under_provisioned"
        elif len(issues) == 0:
            performance_rating = "optimal"
        else:
            performance_rating = "needs_tuning"
        
        return {
            'status': 'analyzed',
            'performance_rating': performance_rating,
            'current_metrics': {
                'avg_total_connections': avg_total_connections,
                'max_total_connections': max_total_connections,
                'avg_active_connections': avg_active_connections,
                'avg_idle_connections': avg_idle_connections,
                'utilization_rate': utilization_rate,
                'avg_connection_wait': avg_connection_wait,
                'avg_query_time': avg_query_time
            },
            'issues': issues,
            'recommendations': recommendations,
            'analysis_period_hours': 24,
            'samples_analyzed': len(history_metrics)
        }
    
    def generate_optimal_config(self) -> PoolConfiguration:
        """
        Generate optimal connection pool configuration
        Task 4.2.3: Optimal configuration generation
        """
        
        analysis = self.analyze_pool_performance()
        current_metrics = analysis.get('current_metrics', {})
        
        # Base calculations on system resources and usage patterns
        system_memory_gb = self.monitor.system_memory_gb
        cpu_cores = self.monitor.cpu_cores
        
        # Calculate optimal max connections
        # Rule of thumb: 2-4 connections per CPU core, adjusted for memory
        base_max_connections = min(
            cpu_cores * 3,  # 3 connections per core
            int(system_memory_gb * 15),  # 15 connections per GB RAM
            200  # Maximum reasonable limit
        )
        
        # Adjust based on current usage patterns
        avg_total = current_metrics.get('avg_total_connections', 10)
        max_used = current_metrics.get('max_total_connections', 10)
        
        if max_used > 0:
            # Add 50% headroom to max observed usage
            calculated_max = int(max_used * 1.5)
            optimal_max = max(base_max_connections, calculated_max)
        else:
            optimal_max = base_max_connections
        
        # Ensure reasonable bounds
        optimal_max = min(optimal_max, 300)  # Hard upper limit
        optimal_max = max(optimal_max, 20)   # Minimum reasonable size
        
        # Calculate min connections (20% of max, minimum 2)
        optimal_min = max(int(optimal_max * 0.2), 2)
        
        # Connection timeouts based on application characteristics
        # PRS system likely has mixed workloads
        connection_timeout = 30  # 30 seconds for connection acquisition
        connection_max_age = 3600  # 1 hour max age
        pool_recycle = 7200  # 2 hours recycle time
        
        # Adjust timeouts based on performance
        avg_query_time = current_metrics.get('avg_query_time', 0.1)
        if avg_query_time > 1.0:  # Slow queries
            connection_timeout = 60  # Longer timeout for slow queries
            connection_max_age = 7200  # Longer max age
        
        optimal_config = PoolConfiguration(
            max_connections=optimal_max,
            min_connections=optimal_min,
            connection_max_age=connection_max_age,
            connection_timeout=connection_timeout,
            pool_recycle=pool_recycle,
            pool_pre_ping=True,  # Always enable health checks
            health_check_interval=300  # 5 minutes
        )
        
        return optimal_config
    
    def apply_configuration(self, config: PoolConfiguration, dry_run: bool = True) -> Dict[str, Any]:
        """
        Apply connection pool configuration
        Task 4.2.3: Configuration application
        """
        
        if dry_run:
            return {
                'status': 'dry_run',
                'message': 'Configuration not applied (dry run mode)',
                'proposed_config': {
                    'max_connections': config.max_connections,
                    'min_connections': config.min_connections,
                    'connection_max_age': config.connection_max_age,
                    'connection_timeout': config.connection_timeout,
                    'pool_recycle': config.pool_recycle,
                    'pool_pre_ping': config.pool_pre_ping
                }
            }
        
        try:
            # Generate Django database configuration
            db_config = self._generate_django_db_config(config)
            
            # In a real implementation, this would update settings and restart connections
            # For now, we'll return the configuration that should be applied
            
            return {
                'status': 'success',
                'message': 'Configuration ready for application',
                'django_config': db_config,
                'instructions': [
                    'Update DATABASES setting in Django settings.py',
                    'Restart Django application to apply changes',
                    'Monitor performance after configuration change'
                ]
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Configuration application failed: {str(e)}'
            }
    
    def _get_current_config(self) -> PoolConfiguration:
        """Get current connection pool configuration"""
        
        db_settings = getattr(settings, 'DATABASES', {}).get('default', {})
        options = db_settings.get('OPTIONS', {})
        
        # Extract current settings (with defaults)
        return PoolConfiguration(
            max_connections=options.get('MAX_CONNS', 20),
            min_connections=options.get('MIN_CONNS', 1),
            connection_max_age=db_settings.get('CONN_MAX_AGE', 0),
            connection_timeout=options.get('CONN_TIMEOUT', 30),
            pool_recycle=options.get('POOL_RECYCLE', 3600),
            pool_pre_ping=options.get('POOL_PRE_PING', False)
        )
    
    def _generate_django_db_config(self, config: PoolConfiguration) -> Dict[str, Any]:
        """Generate Django database configuration"""
        
        return {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': 'your_database_name',  # Would be filled from current config
            'USER': 'your_database_user',  # Would be filled from current config
            'PASSWORD': 'your_database_password',  # Would be filled from current config
            'HOST': 'your_database_host',  # Would be filled from current config
            'PORT': 'your_database_port',  # Would be filled from current config
            'CONN_MAX_AGE': config.connection_max_age,
            'OPTIONS': {
                'MAX_CONNS': config.max_connections,
                'MIN_CONNS': config.min_connections,
                'CONN_TIMEOUT': config.connection_timeout,
                'POOL_RECYCLE': config.pool_recycle,
                'POOL_PRE_PING': config.pool_pre_ping,
                'sslmode': 'require',  # Recommended for production
            }
        }
    
    def _load_optimization_rules(self) -> Dict[str, Any]:
        """Load connection pool optimization rules"""
        
        return {
            'cpu_connection_ratio': 3,  # 3 connections per CPU core
            'memory_connection_ratio': 15,  # 15 connections per GB RAM
            'min_headroom_percentage': 50,  # 50% headroom above max usage
            'idle_threshold_percentage': 60,  # Issue if >60% connections idle
            'utilization_threshold_percentage': 80,  # Issue if >80% utilization
            'connection_wait_threshold_ms': 100,  # Issue if >100ms wait time
            'min_pool_size': 2,  # Minimum connection pool size
            'max_pool_size': 300,  # Maximum connection pool size
        }
    
    def get_configuration_recommendations(self) -> List[str]:
        """Get specific configuration recommendations"""
        
        analysis = self.analyze_pool_performance()
        recommendations = analysis.get('recommendations', [])
        
        # Add specific configuration recommendations
        current_config = self.current_config
        optimal_config = self.generate_optimal_config()
        
        config_recs = []
        
        if optimal_config.max_connections != current_config.max_connections:
            config_recs.append(
                f"Adjust max_connections: {current_config.max_connections} → {optimal_config.max_connections}"
            )
        
        if optimal_config.min_connections != current_config.min_connections:
            config_recs.append(
                f"Adjust min_connections: {current_config.min_connections} → {optimal_config.min_connections}"
            )
        
        if optimal_config.connection_max_age != current_config.connection_max_age:
            config_recs.append(
                f"Adjust connection_max_age: {current_config.connection_max_age}s → {optimal_config.connection_max_age}s"
            )
        
        if not current_config.pool_pre_ping and optimal_config.pool_pre_ping:
            config_recs.append("Enable pool_pre_ping for better connection health")
        
        return recommendations + config_recs
    
    def health_check(self) -> Dict[str, Any]:
        """Perform connection pool health check"""
        
        try:
            # Test connection acquisition
            start_time = time.time()
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
            connection_time = time.time() - start_time
            
            # Get current metrics
            metrics = self.monitor.get_current_metrics()
            
            # Assess health
            health_issues = []
            
            if connection_time > 1.0:
                health_issues.append(f"Slow connection acquisition: {connection_time:.3f}s")
            
            if metrics.connection_errors:
                health_issues.append(f"Recent connection errors: {len(metrics.connection_errors)}")
            
            max_conn_limit = self.monitor._get_max_connections_limit() or 100
            if metrics.total_connections > max_conn_limit * 0.9:
                health_issues.append(f"Near connection limit: {metrics.total_connections}/{max_conn_limit}")
            
            # Overall health status
            if not health_issues:
                status = "healthy"
            elif len(health_issues) == 1:
                status = "warning"
            else:
                status = "critical"
            
            return {
                'status': status,
                'connection_test_time': connection_time,
                'current_connections': metrics.total_connections,
                'max_connections_limit': max_conn_limit,
                'health_issues': health_issues,
                'timestamp': timezone.now().isoformat()
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': timezone.now().isoformat()
            }


# Global instances
db_connection_monitor = DatabaseConnectionMonitor()
connection_pool_optimizer = ConnectionPoolOptimizer(db_connection_monitor)


# Utility functions
def get_connection_metrics() -> ConnectionMetrics:
    """Get current connection metrics"""
    return db_connection_monitor.get_current_metrics()


def analyze_pool_performance() -> Dict[str, Any]:
    """Analyze connection pool performance"""
    return connection_pool_optimizer.analyze_pool_performance()


def get_optimal_config() -> PoolConfiguration:
    """Get optimal connection pool configuration"""
    return connection_pool_optimizer.generate_optimal_config()


def perform_health_check() -> Dict[str, Any]:
    """Perform connection pool health check"""
    return connection_pool_optimizer.health_check()
