"""
Cache Invalidation Optimizer - Task 4.1.2

Optimized cache invalidation system for large organizations with
batch invalidation, intelligent timing, and performance monitoring.
"""

import time
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from django.core.cache import cache, caches
from django.utils import timezone
from django.db import models
from django.db.models.signals import post_save, post_delete, m2m_changed
from django.dispatch import receiver
import fnmatch
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class InvalidationJob:
    """Individual cache invalidation job"""
    keys: List[str]
    patterns: List[str]
    priority: int = 1  # 1=high, 2=medium, 3=low
    batch_size: int = 100
    delay_seconds: float = 0.0
    created_at: datetime = field(default_factory=timezone.now)
    organization_id: Optional[int] = None
    reason: str = ""


@dataclass
class InvalidationMetrics:
    """Cache invalidation performance metrics"""
    total_invalidations: int = 0
    batch_invalidations: int = 0  
    individual_invalidations: int = 0
    avg_batch_time: float = 0.0
    avg_individual_time: float = 0.0
    failed_invalidations: int = 0
    total_keys_invalidated: int = 0
    total_time_saved: float = 0.0


class CacheInvalidationManager:
    """
    Optimized cache invalidation manager with batch processing
    Task 4.1.2: Core invalidation optimization
    """
    
    def __init__(self, max_batch_size: int = 1000, max_queue_size: int = 10000):
        self.max_batch_size = max_batch_size
        self.max_queue_size = max_queue_size
        
        # Invalidation queue with priority levels
        self.high_priority_queue = deque(maxlen=max_queue_size // 3)
        self.medium_priority_queue = deque(maxlen=max_queue_size // 3) 
        self.low_priority_queue = deque(maxlen=max_queue_size // 3)
        
        # Metrics tracking
        self.metrics = InvalidationMetrics()
        self.recent_operations = deque(maxlen=1000)
        
        # Threading
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix='cache_invalidation')
        
        # Configuration
        self.batch_delay = 0.1  # 100ms delay between batches
        self.organization_batch_sizes = {}  # Custom batch sizes per org
        
        # Pattern-based invalidation rules
        self.invalidation_rules = self._load_invalidation_rules()
        
        # Start background processor
        self._start_background_processor()
    
    def schedule_invalidation(
        self, 
        keys: Optional[List[str]] = None,
        patterns: Optional[List[str]] = None,
        priority: int = 2,
        organization_id: Optional[int] = None,
        reason: str = "",
        batch_size: Optional[int] = None,
        delay_seconds: float = 0.0
    ) -> str:
        """
        Schedule cache invalidation with optimization
        Task 4.1.2: Optimized invalidation scheduling
        """
        
        if not keys and not patterns:
            raise ValueError("Either keys or patterns must be provided")
        
        keys = keys or []
        patterns = patterns or []
        
        # Optimize batch size for organization
        if batch_size is None:
            batch_size = self._get_optimal_batch_size(organization_id, len(keys) + len(patterns))
        
        job = InvalidationJob(
            keys=keys,
            patterns=patterns,
            priority=priority,
            batch_size=batch_size,
            delay_seconds=delay_seconds,
            organization_id=organization_id,
            reason=reason
        )
        
        # Add to appropriate priority queue
        with self.lock:
            if priority == 1:
                self.high_priority_queue.append(job)
            elif priority == 2:
                self.medium_priority_queue.append(job)
            else:
                self.low_priority_queue.append(job)
        
        job_id = self._generate_job_id(job)
        logger.info(f"Scheduled cache invalidation job {job_id}: {len(keys)} keys, {len(patterns)} patterns")
        
        return job_id
    
    def invalidate_immediate(
        self, 
        keys: Optional[List[str]] = None,
        patterns: Optional[List[str]] = None,
        organization_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Immediate cache invalidation with optimization
        Task 4.1.2: Optimized immediate invalidation
        """
        
        start_time = time.time()
        
        try:
            keys = keys or []
            patterns = patterns or []
            
            # Expand patterns to keys
            pattern_keys = self._expand_patterns(patterns, organization_id)
            all_keys = list(set(keys + pattern_keys))
            
            # Batch invalidation for efficiency
            if len(all_keys) > self.max_batch_size:
                result = self._batch_invalidate_keys(all_keys, organization_id)
            else:
                result = self._invalidate_keys_batch(all_keys)
            
            execution_time = time.time() - start_time
            
            # Record metrics
            with self.lock:
                self.metrics.individual_invalidations += 1
                if len(all_keys) > 1:
                    self.metrics.batch_invalidations += 1
                self.metrics.total_keys_invalidated += len(all_keys)
                self.metrics.avg_individual_time = (
                    (self.metrics.avg_individual_time * (self.metrics.individual_invalidations - 1) + execution_time)
                    / self.metrics.individual_invalidations
                )
            
            return {
                'success': True,
                'keys_invalidated': len(all_keys),
                'execution_time': execution_time,
                'method': 'batch' if len(all_keys) > 1 else 'individual'
            }
            
        except Exception as e:
            logger.error(f"Immediate cache invalidation failed: {e}")
            
            with self.lock:
                self.metrics.failed_invalidations += 1
            
            return {
                'success': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def invalidate_organization_cache(self, organization_id: int, selective: bool = True) -> Dict[str, Any]:
        """
        Optimized organization-wide cache invalidation
        Task 4.1.2: Large organization optimization
        """
        
        start_time = time.time()
        
        try:
            if selective:
                # Selective invalidation based on organization patterns
                patterns = self._get_organization_cache_patterns(organization_id)
                return self.invalidate_immediate(patterns=patterns, organization_id=organization_id)
            else:
                # Full organization cache clear (last resort)
                pattern = f"org_{organization_id}_*"
                return self.invalidate_immediate(patterns=[pattern], organization_id=organization_id)
                
        except Exception as e:
            logger.error(f"Organization cache invalidation failed for org {organization_id}: {e}")
            return {
                'success': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def _get_optimal_batch_size(self, organization_id: Optional[int], total_items: int) -> int:
        """Calculate optimal batch size for organization"""
        
        # Custom batch size for organization
        if organization_id and organization_id in self.organization_batch_sizes:
            return min(self.organization_batch_sizes[organization_id], self.max_batch_size)
        
        # Adaptive batch size based on total items
        if total_items < 10:
            return total_items
        elif total_items < 100:
            return 50
        elif total_items < 1000:
            return 200
        else:
            return self.max_batch_size
    
    def _expand_patterns(self, patterns: List[str], organization_id: Optional[int]) -> List[str]:
        """
        Expand wildcard patterns to actual cache keys
        Task 4.1.2: Efficient pattern expansion
        """
        
        if not patterns:
            return []
        
        expanded_keys = []
        
        try:
            # Get all cache keys (this might be expensive for large caches)
            cache_backend = cache._cache
            
            if hasattr(cache_backend, 'keys'):
                # Redis backend
                all_keys = cache_backend.keys('*')
                if isinstance(all_keys[0], bytes):
                    all_keys = [key.decode('utf-8') for key in all_keys]
            else:
                # Other backends - use pattern-specific logic
                all_keys = self._get_keys_from_patterns(patterns, organization_id)
            
            # Match patterns
            for pattern in patterns:
                matching_keys = fnmatch.filter(all_keys, pattern)
                expanded_keys.extend(matching_keys)
            
            # Remove duplicates
            expanded_keys = list(set(expanded_keys))
            
        except Exception as e:
            logger.warning(f"Pattern expansion failed, using pattern-based invalidation: {e}")
            expanded_keys = patterns  # Fall back to pattern-based deletion
        
        return expanded_keys
    
    def _get_keys_from_patterns(self, patterns: List[str], organization_id: Optional[int]) -> List[str]:
        """Generate likely keys from patterns for non-Redis backends"""
        
        keys = []
        
        # Common key patterns for the PRS system
        common_prefixes = [
            'user_profile', 'deal_list', 'client_data', 'commission_calc',
            'dashboard_stats', 'notification_count', 'permission_check',
            'organization_data', 'team_info', 'project_data'
        ]
        
        if organization_id:
            for prefix in common_prefixes:
                for i in range(1, 1000):  # Common ID range
                    keys.append(f"{prefix}_{organization_id}_{i}")
                    keys.append(f"org_{organization_id}_{prefix}_{i}")
        
        return keys
    
    def _batch_invalidate_keys(self, keys: List[str], organization_id: Optional[int]) -> Dict[str, Any]:
        """
        Batch invalidation with optimization
        Task 4.1.2: Optimized batch processing
        """
        
        start_time = time.time()
        batch_size = self._get_optimal_batch_size(organization_id, len(keys))
        
        total_invalidated = 0
        batches_processed = 0
        
        # Process in batches
        for i in range(0, len(keys), batch_size):
            batch_keys = keys[i:i + batch_size]
            
            try:
                # Use delete_many if available (more efficient)
                if hasattr(cache, 'delete_many'):
                    cache.delete_many(batch_keys)
                else:
                    # Fall back to individual deletions
                    for key in batch_keys:
                        cache.delete(key)
                
                total_invalidated += len(batch_keys)
                batches_processed += 1
                
                # Small delay between batches to prevent overwhelming the cache
                if i + batch_size < len(keys):
                    time.sleep(self.batch_delay)
                    
            except Exception as e:
                logger.error(f"Batch invalidation failed for batch {batches_processed}: {e}")
                continue
        
        execution_time = time.time() - start_time
        
        return {
            'success': True,
            'keys_invalidated': total_invalidated,
            'batches_processed': batches_processed,
            'execution_time': execution_time,
            'method': 'batch'
        }
    
    def _invalidate_keys_batch(self, keys: List[str]) -> Dict[str, Any]:
        """Invalidate a single batch of keys"""
        
        start_time = time.time()
        
        try:
            if hasattr(cache, 'delete_many'):
                # Use efficient delete_many if available
                cache.delete_many(keys)
            else:
                # Fall back to individual deletions
                for key in keys:
                    cache.delete(key)
            
            return {
                'success': True,
                'keys_invalidated': len(keys),
                'execution_time': time.time() - start_time,
                'method': 'single_batch'
            }
            
        except Exception as e:
            logger.error(f"Keys batch invalidation failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'keys_invalidated': 0,
                'execution_time': time.time() - start_time
            }
    
    def _get_organization_cache_patterns(self, organization_id: int) -> List[str]:
        """Get cache patterns specific to an organization"""
        
        patterns = [
            f"org_{organization_id}_*",
            f"user_profile_{organization_id}_*",
            f"deal_list_{organization_id}_*", 
            f"client_data_{organization_id}_*",
            f"dashboard_stats_{organization_id}_*",
            f"commission_calc_{organization_id}_*",
            f"notification_count_{organization_id}_*",
            f"team_info_{organization_id}_*",
            f"project_data_{organization_id}_*"
        ]
        
        return patterns
    
    def _start_background_processor(self):
        """Start background processor for queued invalidations"""
        
        def process_queue():
            while True:
                try:
                    job = self._get_next_job()
                    if job:
                        self._process_invalidation_job(job)
                    else:
                        time.sleep(0.5)  # Wait if no jobs
                except Exception as e:
                    logger.error(f"Background invalidation processor error: {e}")
                    time.sleep(1)
        
        # Start background thread
        thread = threading.Thread(target=process_queue, daemon=True, name='cache_invalidation_processor')
        thread.start()
        
        logger.info("Cache invalidation background processor started")
    
    def _get_next_job(self) -> Optional[InvalidationJob]:
        """Get next invalidation job from priority queues"""
        
        with self.lock:
            # Check high priority first
            if self.high_priority_queue:
                return self.high_priority_queue.popleft()
            
            # Then medium priority
            if self.medium_priority_queue:
                return self.medium_priority_queue.popleft()
            
            # Finally low priority
            if self.low_priority_queue:
                return self.low_priority_queue.popleft()
        
        return None
    
    def _process_invalidation_job(self, job: InvalidationJob):
        """Process a queued invalidation job"""
        
        start_time = time.time()
        
        try:
            # Apply delay if specified
            if job.delay_seconds > 0:
                time.sleep(job.delay_seconds)
            
            # Execute invalidation
            result = self.invalidate_immediate(
                keys=job.keys,
                patterns=job.patterns,
                organization_id=job.organization_id
            )
            
            execution_time = time.time() - start_time
            
            # Update metrics
            with self.lock:
                self.metrics.total_invalidations += 1
                if result['success']:
                    self.metrics.total_keys_invalidated += result['keys_invalidated']
                    
                    # Calculate time saved by batching
                    estimated_individual_time = result['keys_invalidated'] * 0.001  # 1ms per key
                    time_saved = max(0, estimated_individual_time - result['execution_time'])
                    self.metrics.total_time_saved += time_saved
                else:
                    self.metrics.failed_invalidations += 1
            
            # Log result
            job_id = self._generate_job_id(job)
            if result['success']:
                logger.info(
                    f"Completed invalidation job {job_id}: "
                    f"{result['keys_invalidated']} keys in {execution_time:.3f}s"
                )
            else:
                logger.error(f"Failed invalidation job {job_id}: {result['error']}")
                
        except Exception as e:
            logger.error(f"Error processing invalidation job: {e}")
            
            with self.lock:
                self.metrics.failed_invalidations += 1
    
    def _load_invalidation_rules(self) -> Dict[str, List[str]]:
        """Load model-based invalidation rules"""
        
        return {
            # Deal model changes
            'Deal': [
                'deal_list_org_{organization}_*',
                'deal_detail_{id}',
                'dashboard_stats_{organization}_*',
                'commission_calc_{organization}_*'
            ],
            
            # User model changes
            'User': [
                'user_profile_{id}',
                'user_permissions_{id}',
                'team_info_{organization}_*'
            ],
            
            # Client model changes  
            'Client': [
                'client_data_{id}',
                'client_list_{organization}_*',
                'deal_list_org_{organization}_*'
            ],
            
            # Organization model changes
            'Organization': [
                'org_{id}_*',
                'dashboard_stats_{id}_*'
            ]
        }
    
    def _generate_job_id(self, job: InvalidationJob) -> str:
        """Generate unique job ID"""
        
        content = f"{job.keys}{job.patterns}{job.created_at.isoformat()}"
        return hashlib.md5(content.encode()).hexdigest()[:8]
    
    def get_invalidation_metrics(self) -> InvalidationMetrics:
        """Get current invalidation performance metrics"""
        
        with self.lock:
            return InvalidationMetrics(
                total_invalidations=self.metrics.total_invalidations,
                batch_invalidations=self.metrics.batch_invalidations,
                individual_invalidations=self.metrics.individual_invalidations,
                avg_batch_time=self.metrics.avg_batch_time,
                avg_individual_time=self.metrics.avg_individual_time,
                failed_invalidations=self.metrics.failed_invalidations,
                total_keys_invalidated=self.metrics.total_keys_invalidated,
                total_time_saved=self.metrics.total_time_saved
            )
    
    def get_queue_status(self) -> Dict[str, int]:
        """Get current queue status"""
        
        with self.lock:
            return {
                'high_priority': len(self.high_priority_queue),
                'medium_priority': len(self.medium_priority_queue),
                'low_priority': len(self.low_priority_queue),
                'total_queued': (
                    len(self.high_priority_queue) + 
                    len(self.medium_priority_queue) + 
                    len(self.low_priority_queue)
                )
            }
    
    def optimize_organization_settings(self, organization_id: int, batch_size: int):
        """Optimize invalidation settings for specific organization"""
        
        self.organization_batch_sizes[organization_id] = min(batch_size, self.max_batch_size)
        logger.info(f"Optimized invalidation batch size for org {organization_id}: {batch_size}")
    
    def clear_queues(self):
        """Clear all invalidation queues"""
        
        with self.lock:
            self.high_priority_queue.clear()
            self.medium_priority_queue.clear()
            self.low_priority_queue.clear()
        
        logger.info("All invalidation queues cleared")


# Global cache invalidation manager instance
cache_invalidation_manager = CacheInvalidationManager()


class SmartCacheInvalidation:
    """
    Smart cache invalidation based on model changes
    Task 4.1.2: Intelligent invalidation triggers
    """
    
    @staticmethod
    def invalidate_for_model(instance: models.Model, action: str = 'save'):
        """
        Invalidate cache based on model instance changes
        Task 4.1.2: Model-based invalidation
        """
        
        model_name = instance.__class__.__name__
        
        # Get organization ID if available
        organization_id = getattr(instance, 'organization_id', None)
        if not organization_id and hasattr(instance, 'organization'):
            organization_id = getattr(instance.organization, 'id', None)
        
        # Generate invalidation patterns based on model
        patterns = SmartCacheInvalidation._get_patterns_for_model(
            model_name, instance, organization_id
        )
        
        if patterns:
            cache_invalidation_manager.schedule_invalidation(
                patterns=patterns,
                priority=1 if action == 'delete' else 2,
                organization_id=organization_id,
                reason=f"{model_name} {action}"
            )
    
    @staticmethod
    def _get_patterns_for_model(model_name: str, instance: models.Model, organization_id: Optional[int]) -> List[str]:
        """Get cache patterns to invalidate for model changes"""
        
        patterns = []
        instance_id = getattr(instance, 'id', None)
        
        # Model-specific patterns
        if model_name == 'Deal':
            patterns.extend([
                f'deal_detail_{instance_id}',
                f'deal_list_org_{organization_id}_*',
                f'dashboard_stats_{organization_id}_*',
                f'commission_calc_{organization_id}_*'
            ])
            
            # Client-related patterns
            client_id = getattr(instance, 'client_id', None)
            if client_id:
                patterns.append(f'client_deals_{client_id}_*')
        
        elif model_name == 'User':
            patterns.extend([
                f'user_profile_{instance_id}',
                f'user_permissions_{instance_id}',
                f'team_info_{organization_id}_*'
            ])
        
        elif model_name == 'Client':
            patterns.extend([
                f'client_data_{instance_id}',
                f'client_list_{organization_id}_*',
                f'client_deals_{instance_id}_*'
            ])
        
        elif model_name == 'Organization':
            patterns.extend([
                f'org_{instance_id}_*',
                f'dashboard_stats_{instance_id}_*'
            ])
        
        elif model_name == 'Payment':
            deal_id = getattr(instance, 'deal_id', None)
            if deal_id:
                patterns.extend([
                    f'deal_detail_{deal_id}',
                    f'payment_history_{deal_id}_*',
                    f'dashboard_stats_{organization_id}_*'
                ])
        
        return patterns


# Django signal handlers for automatic cache invalidation
@receiver([post_save, post_delete])
def handle_model_cache_invalidation(sender, instance, **kwargs):
    """
    Handle automatic cache invalidation on model changes
    Task 4.1.2: Automatic invalidation triggers
    """
    
    # Skip for certain models to avoid excessive invalidation
    skip_models = ['LogEntry', 'Session', 'ContentType']
    if sender.__name__ in skip_models:
        return
    
    try:
        action = 'delete' if kwargs.get('signal') == post_delete else 'save'
        SmartCacheInvalidation.invalidate_for_model(instance, action)
        
    except Exception as e:
        logger.error(f"Error in automatic cache invalidation: {e}")


# Utility functions for manual invalidation
def invalidate_user_cache(user_id: int, organization_id: Optional[int] = None):
    """Invalidate all cache entries for a user"""
    
    patterns = [
        f'user_profile_{user_id}',
        f'user_permissions_{user_id}',
        f'user_dashboard_{user_id}_*'
    ]
    
    if organization_id:
        patterns.append(f'team_info_{organization_id}_*')
    
    return cache_invalidation_manager.invalidate_immediate(
        patterns=patterns,
        organization_id=organization_id
    )


def invalidate_deal_cache(deal_id: int, organization_id: Optional[int] = None):
    """Invalidate all cache entries for a deal"""
    
    patterns = [
        f'deal_detail_{deal_id}',
        f'deal_payments_{deal_id}_*',
        f'deal_history_{deal_id}_*'
    ]
    
    if organization_id:
        patterns.extend([
            f'deal_list_org_{organization_id}_*',
            f'dashboard_stats_{organization_id}_*'
        ])
    
    return cache_invalidation_manager.invalidate_immediate(
        patterns=patterns,
        organization_id=organization_id
    )


def invalidate_organization_cache(organization_id: int, selective: bool = True):
    """Invalidate cache for an entire organization"""
    
    return cache_invalidation_manager.invalidate_organization_cache(
        organization_id=organization_id,
        selective=selective
    )
