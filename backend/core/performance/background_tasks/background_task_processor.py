"""
Background Task Processor - Refactored Module

This file serves as the main entry point for background task processing,
importing from modular task files for better organization.

The original 810-line background_task_processor.py file has been broken down into:
- deal_processing.py: Deal workflow processing tasks
- file_processing.py: File upload and processing tasks  
- notification_tasks.py: Email notification tasks
- task_monitoring.py: Task monitoring and management

This refactoring reduces complexity and improves maintainability.
"""

from celery.utils.log import get_task_logger
from django.utils import timezone
from typing import Dict, List, Optional, Any

# Task logger
logger = get_task_logger(__name__)


class BackgroundTaskProcessor:
    """
    Central processor for background tasks with monitoring and retry logic
    """
    
    # Task priorities
    PRIORITY_HIGH = 'high'
    PRIORITY_MEDIUM = 'medium'
    PRIORITY_LOW = 'low'
    
    # Retry settings
    MAX_RETRIES = 3
    RETRY_BACKOFF = True
    RETRY_JITTER = True
    
    @classmethod
    def get_task_status(cls, task_id: str) -> Dict[str, Any]:
        """Get status of a background task - delegated to TaskMonitor"""
        from .task_monitoring import TaskMonitor
        return TaskMonitor.get_task_status(task_id)
    
    @classmethod
    def get_all_task_statuses(cls, task_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get statuses for multiple tasks - delegated to TaskMonitor"""
        from .task_monitoring import TaskMonitor
        return TaskMonitor.get_all_task_statuses(task_ids)
    
    @classmethod
    def revoke_task(cls, task_id: str, terminate: bool = False) -> bool:
        """Revoke a running task - delegated to TaskMonitor"""
        from .task_monitoring import TaskMonitor
        return TaskMonitor.revoke_task(task_id, terminate)
    
    @classmethod
    def queue_deal_processing(cls, deal_id: int, workflow_action: str, user_id: Optional[int] = None, priority: str = PRIORITY_MEDIUM):
        """Queue a deal processing task"""
        from .deal_processing import process_deal_workflow
        
        task_kwargs = {
            'deal_id': deal_id,
            'workflow_action': workflow_action,
            'user_id': user_id
        }
        
        if priority == cls.PRIORITY_HIGH:
            return process_deal_workflow.apply_async(kwargs=task_kwargs, priority=9)
        elif priority == cls.PRIORITY_LOW:
            return process_deal_workflow.apply_async(kwargs=task_kwargs, priority=3)
        else:
            return process_deal_workflow.apply_async(kwargs=task_kwargs, priority=5)
    
    @classmethod
    def queue_file_processing(cls, file_type: str, **kwargs):
        """Queue a file processing task"""
        if file_type == 'profile_picture':
            from .file_processing import process_profile_picture
            return process_profile_picture.apply_async(kwargs=kwargs)
        elif file_type == 'deal_attachment':
            from .file_processing import process_deal_attachment
            return process_deal_attachment.apply_async(kwargs=kwargs)
        else:
            raise ValueError(f"Unknown file processing type: {file_type}")
    
    @classmethod
    def queue_notification(cls, notification_type: str, **kwargs):
        """Queue a notification task"""
        if notification_type == 'password_request':
            from .notification_tasks import send_password_request_notification
            return send_password_request_notification.apply_async(kwargs=kwargs)
        elif notification_type == 'deal_notification':
            from .notification_tasks import send_deal_notification
            return send_deal_notification.apply_async(kwargs=kwargs)
        else:
            raise ValueError(f"Unknown notification type: {notification_type}")


# Import all tasks from modular files for backward compatibility
from .deal_processing import (
    process_deal_workflow
)

from .file_processing import (
    process_profile_picture,
    process_deal_attachment
)

from .notification_tasks import (
    send_password_request_notification,
    send_deal_notification
)

from .task_monitoring import (
    monitor_background_tasks,
    cleanup_failed_tasks,
    TaskMonitor
)

# Make all imports available at module level for backward compatibility
__all__ = [
    # Main processor class
    'BackgroundTaskProcessor',
    
    # Deal processing tasks
    'process_deal_workflow',
    
    # File processing tasks
    'process_profile_picture',
    'process_deal_attachment',
    
    # Notification tasks
    'send_password_request_notification',
    'send_deal_notification',
    
    # Monitoring tasks
    'monitor_background_tasks',
    'cleanup_failed_tasks',
    'TaskMonitor'
]
