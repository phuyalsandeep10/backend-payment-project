"""
Background Tasks - Compatibility Layer

Background task functionality has been moved to core.performance.background_tasks
This file provides backward compatibility imports.
"""

# Import all background task functionality from new location
from core.performance.background_tasks.background_task_processor import (
    BackgroundTaskProcessor
)
from core.performance.background_tasks.automated_business_processes import (
    AutomatedBusinessProcessManager  
)
from core.performance.background_tasks.task_monitoring import (
    TaskMonitor
)

# Make all imports available at module level for backward compatibility  
__all__ = [
    'BackgroundTaskProcessor',
    'AutomatedBusinessProcessManager', 
    'TaskMonitor'
]
