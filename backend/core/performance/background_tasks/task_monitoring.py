"""
Task Monitoring and Management

This module handles monitoring and management of background tasks including:
- Task status monitoring
- Failed task cleanup
- Performance metrics

Extracted from background_task_processor.py for better organization.
"""

from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from typing import Dict, Any

# Task logger
logger = get_task_logger(__name__)


@shared_task
def monitor_background_tasks():
    """
    Monitor background tasks and report on their status
    """
    try:
        from celery import current_app
        
        logger.info("Starting background task monitoring")
        
        # Get active tasks
        inspect = current_app.control.inspect()
        
        active_tasks = inspect.active()
        scheduled_tasks = inspect.scheduled()
        reserved_tasks = inspect.reserved()
        
        monitoring_report = {
            'timestamp': timezone.now().isoformat(),
            'active_tasks': active_tasks or {},
            'scheduled_tasks': scheduled_tasks or {},
            'reserved_tasks': reserved_tasks or {},
            'summary': {
                'total_active': sum(len(tasks) for tasks in (active_tasks or {}).values()),
                'total_scheduled': sum(len(tasks) for tasks in (scheduled_tasks or {}).values()),
                'total_reserved': sum(len(tasks) for tasks in (reserved_tasks or {}).values())
            }
        }
        
        logger.info(f"Background task monitoring completed: {monitoring_report['summary']}")
        
        return monitoring_report
        
    except Exception as e:
        logger.error(f"Background task monitoring failed: {str(e)}")
        raise


@shared_task
def cleanup_failed_tasks():
    """
    Clean up failed tasks and retry if appropriate
    """
    try:
        logger.info("Starting failed task cleanup")
        
        # This would implement cleanup logic for failed tasks
        # For now, we'll just log the action
        
        cleanup_results = {
            'timestamp': timezone.now().isoformat(),
            'failed_tasks_cleaned': 0,
            'tasks_retried': 0
        }
        
        logger.info("Failed task cleanup completed")
        
        return cleanup_results
        
    except Exception as e:
        logger.error(f"Failed task cleanup failed: {str(e)}")
        raise


class TaskMonitor:
    """
    Utility class for task monitoring and management
    """
    
    @classmethod
    def get_task_status(cls, task_id: str) -> Dict[str, Any]:
        """Get status of a background task"""
        try:
            from celery.result import AsyncResult
            
            result = AsyncResult(task_id)
            
            return {
                'task_id': task_id,
                'status': result.status,
                'result': result.result if result.ready() else None,
                'traceback': result.traceback if result.failed() else None,
                'date_done': result.date_done.isoformat() if result.date_done else None,
                'successful': result.successful()
            }
            
        except Exception as e:
            logger.error(f"Failed to get task status for {task_id}: {str(e)}")
            return {
                'task_id': task_id,
                'status': 'ERROR',
                'error': str(e)
            }
    
    @classmethod
    def get_all_task_statuses(cls, task_ids: list) -> Dict[str, Dict[str, Any]]:
        """Get statuses for multiple tasks"""
        statuses = {}
        for task_id in task_ids:
            statuses[task_id] = cls.get_task_status(task_id)
        return statuses
    
    @classmethod
    def revoke_task(cls, task_id: str, terminate: bool = False) -> bool:
        """Revoke a running task"""
        try:
            from celery import current_app
            
            current_app.control.revoke(task_id, terminate=terminate)
            logger.info(f"Task {task_id} revoked (terminate={terminate})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke task {task_id}: {str(e)}")
            return False
