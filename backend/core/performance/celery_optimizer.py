"""
Celery Task Processing Optimizer - Task 4.4.1

Optimizes Celery task queue configuration and implements comprehensive
task monitoring and error handling.
"""

import logging
import time
from typing import Dict, List, Optional, Any
from functools import wraps
from celery import current_app
from celery.signals import task_prerun, task_postrun, task_failure, task_retry
from django.utils import timezone
from collections import defaultdict, deque
import json

logger = logging.getLogger(__name__)


class CeleryTaskMonitor:
    """
    Celery task performance monitoring system
    Task 4.4.1: Task monitoring and optimization
    """
    
    def __init__(self):
        self.task_stats = defaultdict(lambda: {
            'total_runs': 0,
            'total_time': 0.0,
            'avg_time': 0.0,
            'failures': 0,
            'retries': 0,
            'success_rate': 100.0
        })
        self.recent_failures = deque(maxlen=100)
        self.slow_tasks = deque(maxlen=50)
        self.slow_threshold = 30.0  # 30 seconds
    
    def record_task_execution(self, task_name: str, execution_time: float, 
                            success: bool = True, retry_count: int = 0):
        """Record task execution metrics"""
        
        stats = self.task_stats[task_name]
        stats['total_runs'] += 1
        
        if success:
            stats['total_time'] += execution_time
            stats['avg_time'] = stats['total_time'] / (stats['total_runs'] - stats['failures'])
            
            # Track slow tasks
            if execution_time > self.slow_threshold:
                self.slow_tasks.append({
                    'task_name': task_name,
                    'execution_time': execution_time,
                    'timestamp': timezone.now()
                })
        else:
            stats['failures'] += 1
            self.recent_failures.append({
                'task_name': task_name,
                'timestamp': timezone.now(),
                'retry_count': retry_count
            })
        
        if retry_count > 0:
            stats['retries'] += retry_count
        
        # Calculate success rate
        if stats['total_runs'] > 0:
            stats['success_rate'] = ((stats['total_runs'] - stats['failures']) / stats['total_runs']) * 100
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get Celery performance summary"""
        
        total_tasks = sum(stats['total_runs'] for stats in self.task_stats.values())
        total_failures = sum(stats['failures'] for stats in self.task_stats.values())
        total_retries = sum(stats['retries'] for stats in self.task_stats.values())
        
        # Find slowest tasks
        slowest_tasks = sorted(
            [(name, stats['avg_time']) for name, stats in self.task_stats.items() 
             if stats['avg_time'] > 0],
            key=lambda x: x[1], reverse=True
        )[:10]
        
        # Find tasks with high failure rates
        failing_tasks = sorted(
            [(name, stats['success_rate']) for name, stats in self.task_stats.items() 
             if stats['success_rate'] < 90 and stats['total_runs'] >= 5],
            key=lambda x: x[1]
        )[:10]
        
        return {
            'total_tasks_executed': total_tasks,
            'total_failures': total_failures,
            'total_retries': total_retries,
            'overall_success_rate': ((total_tasks - total_failures) / max(total_tasks, 1)) * 100,
            'slowest_tasks': slowest_tasks,
            'failing_tasks': failing_tasks,
            'recent_failures_count': len(self.recent_failures),
            'slow_tasks_count': len(self.slow_tasks)
        }


class CeleryOptimizer:
    """
    Celery configuration optimization system
    Task 4.4.1: Configuration optimization
    """
    
    def __init__(self):
        self.monitor = CeleryTaskMonitor()
        self.optimal_config = {}
    
    def generate_optimal_config(self) -> Dict[str, Any]:
        """
        Generate optimal Celery configuration
        Task 4.4.1: Configuration generation
        """
        
        # Base configuration optimizations
        config = {
            # Worker configuration
            'worker_concurrency': 4,  # Adjust based on CPU cores
            'worker_prefetch_multiplier': 1,  # Prevent worker hogging
            'worker_max_tasks_per_child': 1000,  # Prevent memory leaks
            'worker_disable_rate_limits': False,
            
            # Task routing and priorities
            'task_routes': {
                'apps.*.tasks.high_priority_*': {'queue': 'high_priority'},
                'apps.*.tasks.low_priority_*': {'queue': 'low_priority'},
                'apps.deals.tasks.*': {'queue': 'deals'},
                'apps.notifications.tasks.*': {'queue': 'notifications'},
            },
            
            # Task execution settings
            'task_acks_late': True,  # Acknowledge after completion
            'task_reject_on_worker_lost': True,  # Retry on worker loss
            'task_track_started': True,  # Track task state
            
            # Retry configuration
            'task_annotations': {
                '*': {
                    'rate_limit': '100/m',  # Default rate limit
                    'time_limit': 300,  # 5 minutes max
                    'soft_time_limit': 240,  # 4 minutes soft limit
                    'retry_kwargs': {'max_retries': 3, 'countdown': 60},
                }
            },
            
            # Result backend optimization
            'result_expires': 3600,  # 1 hour
            'result_backend_transport_options': {
                'master_name': 'mymaster',
                'retry_on_timeout': True,
                'socket_keepalive': True,
                'socket_keepalive_options': {
                    'TCP_KEEPIDLE': 1,
                    'TCP_KEEPINTVL': 3,
                    'TCP_KEEPCNT': 5,
                }
            },
            
            # Monitoring
            'worker_send_task_events': True,
            'task_send_sent_event': True,
            
            # Queue configuration
            'task_default_queue': 'default',
            'task_queues': {
                'default': {'routing_key': 'default'},
                'high_priority': {'routing_key': 'high_priority'},
                'low_priority': {'routing_key': 'low_priority'},
                'deals': {'routing_key': 'deals'},
                'notifications': {'routing_key': 'notifications'},
            }
        }
        
        return config
    
    def optimize_task_retry_strategy(self, task_name: str) -> Dict[str, Any]:
        """
        Generate optimized retry strategy for a task
        Task 4.4.1: Retry strategy optimization
        """
        
        stats = self.monitor.task_stats.get(task_name, {})
        failure_rate = 100 - stats.get('success_rate', 100)
        avg_time = stats.get('avg_time', 0)
        
        # Base retry configuration
        retry_config = {
            'autoretry_for': (Exception,),
            'retry_kwargs': {
                'max_retries': 3,
                'countdown': 60
            }
        }
        
        # Adjust based on failure patterns
        if failure_rate > 20:  # High failure rate
            retry_config['retry_kwargs']['max_retries'] = 5
            retry_config['retry_kwargs']['countdown'] = 120  # Longer delay
        elif failure_rate < 5:  # Very reliable task
            retry_config['retry_kwargs']['max_retries'] = 2
            retry_config['retry_kwargs']['countdown'] = 30  # Shorter delay
        
        # Adjust based on execution time
        if avg_time > 60:  # Long-running tasks
            retry_config['retry_kwargs']['countdown'] = 300  # 5 minute delay
        elif avg_time < 5:  # Quick tasks
            retry_config['retry_kwargs']['countdown'] = 10  # Quick retry
        
        return retry_config
    
    def create_monitoring_dashboard_data(self) -> Dict[str, Any]:
        """Create monitoring dashboard data"""
        
        performance_summary = self.monitor.get_performance_summary()
        
        # Recent task activity
        recent_activity = {
            'recent_failures': [
                {
                    'task': failure['task_name'],
                    'timestamp': failure['timestamp'].isoformat(),
                    'retry_count': failure['retry_count']
                }
                for failure in list(self.monitor.recent_failures)[-10:]
            ],
            'slow_tasks': [
                {
                    'task': task['task_name'],
                    'execution_time': task['execution_time'],
                    'timestamp': task['timestamp'].isoformat()
                }
                for task in list(self.monitor.slow_tasks)[-10:]
            ]
        }
        
        # Optimization recommendations
        recommendations = []
        
        if performance_summary['overall_success_rate'] < 95:
            recommendations.append({
                'type': 'reliability',
                'priority': 'high',
                'message': 'Low success rate detected - review task error handling'
            })
        
        if performance_summary['slow_tasks_count'] > 10:
            recommendations.append({
                'type': 'performance',
                'priority': 'medium',
                'message': 'Multiple slow tasks detected - consider optimization'
            })
        
        return {
            'performance_summary': performance_summary,
            'recent_activity': recent_activity,
            'recommendations': recommendations,
            'optimal_config': self.generate_optimal_config()
        }


# Global instances
celery_monitor = CeleryTaskMonitor()
celery_optimizer = CeleryOptimizer()

# Task monitoring decorators
def monitored_task(func):
    """Decorator to monitor Celery task performance"""
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        task_name = func.__name__
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            celery_monitor.record_task_execution(
                task_name, execution_time, success=True
            )
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            celery_monitor.record_task_execution(
                task_name, execution_time, success=False
            )
            
            logger.error(f"Task {task_name} failed after {execution_time:.2f}s: {e}")
            raise
    
    return wrapper

# Signal handlers for automatic monitoring
@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **kwds):
    """Handle task start"""
    logger.info(f"Starting task: {task.name} [{task_id}]")

@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, 
                        retval=None, state=None, **kwds):
    """Handle task completion"""
    logger.info(f"Completed task: {task.name} [{task_id}] - State: {state}")

@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, traceback=None, einfo=None, **kwds):
    """Handle task failure"""
    logger.error(f"Task failed: {sender.name} [{task_id}] - {exception}")

@task_retry.connect
def task_retry_handler(sender=None, task_id=None, reason=None, einfo=None, **kwds):
    """Handle task retry"""
    logger.warning(f"Task retry: {sender.name} [{task_id}] - {reason}")

# Utility functions
def get_celery_performance_summary():
    """Get Celery performance summary"""
    return celery_monitor.get_performance_summary()

def get_optimal_celery_config():
    """Get optimal Celery configuration"""
    return celery_optimizer.generate_optimal_config()
