"""
Core Performance Module

Extracted from core_config to reduce complexity and improve organization.
Task 2.2.3 - Core Config Decomposition  

This module contains all performance optimization components:
- Caching strategy and management
- API response optimization
- Database performance optimization
- Query performance middleware
- Response rendering optimization
- Performance monitoring and analysis
- Background task processing (moved from core_config)
"""

# Version info
__version__ = '1.0.0'
__description__ = 'PRS Core Performance Module'

# Lazy imports to avoid Django startup issues
BACKGROUND_TASKS_AVAILABLE = True
CACHING_AVAILABLE = True  
DATABASE_OPTIMIZATION_AVAILABLE = True

def get_background_task_processor():
    """Lazy import for BackgroundTaskProcessor"""
    try:
        from .background_tasks.background_task_processor import BackgroundTaskProcessor
        return BackgroundTaskProcessor
    except ImportError:
        return None

def get_cache_manager():
    """Lazy import for StrategicCacheManager"""
    try:
        from .strategic_cache_manager import StrategicCacheManager
        return StrategicCacheManager
    except ImportError:
        return None

def get_database_optimizer():
    """Lazy import for DatabaseOptimizer"""
    try:
        from .database_optimizer import DatabaseOptimizer
        return DatabaseOptimizer
    except ImportError:
        return None

# Build __all__ based on available components
__all__ = []

if BACKGROUND_TASKS_AVAILABLE:
    __all__.extend(['get_background_task_processor'])

if CACHING_AVAILABLE:
    __all__.extend(['get_cache_manager'])

if DATABASE_OPTIMIZATION_AVAILABLE:
    __all__.extend(['get_database_optimizer'])