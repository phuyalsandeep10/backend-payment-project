"""
Cache Warming System - Task 4.1.3

Proactive cache population system with automated warming, predictive caching,
and background refresh for critical data.
"""

import time
import logging
import threading
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from django.core.cache import cache
from django.utils import timezone
from django.db import models
from django.db.models import Q, Count
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


@dataclass
class WarmingJob:
    """Cache warming job definition"""
    key: str
    data_source: Callable[[], Any]
    priority: int = 1  # 1=critical, 2=high, 3=normal, 4=low
    ttl: int = 3600  # Default 1 hour
    dependencies: List[str] = field(default_factory=list)
    organization_id: Optional[int] = None
    category: str = "general"
    created_at: datetime = field(default_factory=timezone.now)
    last_warmed: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0


@dataclass
class WarmingMetrics:
    """Cache warming performance metrics"""
    total_warming_jobs: int = 0
    successful_warmings: int = 0
    failed_warmings: int = 0
    avg_warming_time: float = 0.0
    total_data_warmed: int = 0  # Size in bytes
    cache_hit_improvement: float = 0.0
    predictive_hits: int = 0


class CacheDataSource(ABC):
    """Abstract base class for cache data sources"""
    
    @abstractmethod
    def get_data(self) -> Any:
        """Get data to cache"""
        pass
    
    @abstractmethod
    def get_dependencies(self) -> List[str]:
        """Get list of dependencies that would invalidate this data"""
        pass
    
    @abstractmethod
    def get_ttl(self) -> int:
        """Get time-to-live for this data"""
        pass


class OrganizationDataSource(CacheDataSource):
    """Data source for organization-related cache entries"""
    
    def __init__(self, organization_id: int, data_type: str):
        self.organization_id = organization_id
        self.data_type = data_type
    
    def get_data(self) -> Any:
        """Get organization data"""
        if self.data_type == 'dashboard_stats':
            return self._get_dashboard_stats()
        elif self.data_type == 'deal_list':
            return self._get_deal_list()
        elif self.data_type == 'client_list':
            return self._get_client_list()
        elif self.data_type == 'team_info':
            return self._get_team_info()
        else:
            return {}
    
    def _get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics"""
        try:
            from apps.deals.models import Deal
            from apps.clients.models import Client
            from django.db.models import Sum, Count
            
            stats = {
                'total_deals': Deal.objects.filter(organization_id=self.organization_id).count(),
                'total_clients': Client.objects.filter(organization_id=self.organization_id).count(),
                'total_deal_value': Deal.objects.filter(
                    organization_id=self.organization_id
                ).aggregate(total=Sum('deal_value'))['total'] or 0,
                'recent_deals': Deal.objects.filter(
                    organization_id=self.organization_id,
                    created_at__gte=timezone.now() - timedelta(days=30)
                ).count(),
                'timestamp': timezone.now().isoformat()
            }
            return stats
        except Exception as e:
            logger.error(f"Error getting dashboard stats for org {self.organization_id}: {e}")
            return {}
    
    def _get_deal_list(self) -> List[Dict[str, Any]]:
        """Get deal list for organization"""
        try:
            from apps.deals.models import Deal
            
            deals = Deal.objects.filter(
                organization_id=self.organization_id
            ).select_related('client', 'created_by').order_by('-created_at')[:100]
            
            deal_list = []
            for deal in deals:
                deal_list.append({
                    'id': deal.id,
                    'deal_id': deal.deal_id,
                    'deal_name': deal.deal_name,
                    'client_name': deal.client.client_name if deal.client else None,
                    'deal_value': str(deal.deal_value),
                    'payment_status': deal.payment_status,
                    'created_at': deal.created_at.isoformat()
                })
            
            return deal_list
        except Exception as e:
            logger.error(f"Error getting deal list for org {self.organization_id}: {e}")
            return []
    
    def _get_client_list(self) -> List[Dict[str, Any]]:
        """Get client list for organization"""
        try:
            from apps.clients.models import Client
            
            clients = Client.objects.filter(
                organization_id=self.organization_id
            ).order_by('client_name')[:100]
            
            client_list = []
            for client in clients:
                client_list.append({
                    'id': client.id,
                    'client_name': client.client_name,
                    'email': getattr(client, 'email', ''),
                    'contact_number': getattr(client, 'contact_number', ''),
                    'created_at': client.created_at.isoformat()
                })
            
            return client_list
        except Exception as e:
            logger.error(f"Error getting client list for org {self.organization_id}: {e}")
            return []
    
    def _get_team_info(self) -> Dict[str, Any]:
        """Get team information for organization"""
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            team_members = User.objects.filter(
                organization_id=self.organization_id
            ).select_related('role')
            
            team_data = {
                'total_members': team_members.count(),
                'members': [],
                'roles': defaultdict(int)
            }
            
            for member in team_members[:50]:  # Limit to 50 members
                team_data['members'].append({
                    'id': member.id,
                    'name': member.get_full_name(),
                    'email': member.email,
                    'role': member.role.name if hasattr(member, 'role') and member.role else 'Unknown'
                })
                
                role_name = member.role.name if hasattr(member, 'role') and member.role else 'Unknown'
                team_data['roles'][role_name] += 1
            
            return team_data
        except Exception as e:
            logger.error(f"Error getting team info for org {self.organization_id}: {e}")
            return {}
    
    def get_dependencies(self) -> List[str]:
        """Get dependencies for this data source"""
        deps = [f"org_{self.organization_id}_*"]
        
        if self.data_type == 'dashboard_stats':
            deps.extend([
                f"deal_list_{self.organization_id}_*",
                f"client_list_{self.organization_id}_*"
            ])
        elif self.data_type == 'deal_list':
            deps.append(f"deal_*_{self.organization_id}")
        elif self.data_type == 'client_list':
            deps.append(f"client_*_{self.organization_id}")
        elif self.data_type == 'team_info':
            deps.append(f"user_*_{self.organization_id}")
        
        return deps
    
    def get_ttl(self) -> int:
        """Get TTL based on data type"""
        ttl_mapping = {
            'dashboard_stats': 1800,  # 30 minutes
            'deal_list': 3600,        # 1 hour
            'client_list': 7200,      # 2 hours
            'team_info': 14400        # 4 hours
        }
        return ttl_mapping.get(self.data_type, 3600)


class UserDataSource(CacheDataSource):
    """Data source for user-related cache entries"""
    
    def __init__(self, user_id: int, data_type: str):
        self.user_id = user_id
        self.data_type = data_type
    
    def get_data(self) -> Any:
        """Get user data"""
        if self.data_type == 'profile':
            return self._get_user_profile()
        elif self.data_type == 'permissions':
            return self._get_user_permissions()
        elif self.data_type == 'dashboard':
            return self._get_user_dashboard_data()
        else:
            return {}
    
    def _get_user_profile(self) -> Dict[str, Any]:
        """Get user profile data"""
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            user = User.objects.select_related('role', 'organization').get(id=self.user_id)
            
            profile = {
                'id': user.id,
                'email': user.email,
                'name': user.get_full_name(),
                'role': user.role.name if hasattr(user, 'role') and user.role else None,
                'organization': user.organization.name if hasattr(user, 'organization') and user.organization else None,
                'is_active': user.is_active,
                'last_login': user.last_login.isoformat() if user.last_login else None
            }
            return profile
        except Exception as e:
            logger.error(f"Error getting user profile for user {self.user_id}: {e}")
            return {}
    
    def _get_user_permissions(self) -> List[str]:
        """Get user permissions"""
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            user = User.objects.get(id=self.user_id)
            permissions = list(user.get_all_permissions())
            
            return permissions
        except Exception as e:
            logger.error(f"Error getting user permissions for user {self.user_id}: {e}")
            return []
    
    def _get_user_dashboard_data(self) -> Dict[str, Any]:
        """Get user dashboard data"""
        try:
            from apps.deals.models import Deal
            from django.db.models import Sum, Count
            
            user_deals = Deal.objects.filter(created_by_id=self.user_id)
            
            dashboard_data = {
                'total_deals': user_deals.count(),
                'total_deal_value': user_deals.aggregate(
                    total=Sum('deal_value')
                )['total'] or 0,
                'recent_deals': user_deals.filter(
                    created_at__gte=timezone.now() - timedelta(days=7)
                ).count(),
                'pending_deals': user_deals.filter(
                    payment_status='pending'
                ).count()
            }
            
            return dashboard_data
        except Exception as e:
            logger.error(f"Error getting user dashboard data for user {self.user_id}: {e}")
            return {}
    
    def get_dependencies(self) -> List[str]:
        """Get dependencies for user data"""
        deps = [f"user_{self.user_id}_*"]
        
        if self.data_type == 'dashboard':
            deps.append(f"deal_*_user_{self.user_id}")
        
        return deps
    
    def get_ttl(self) -> int:
        """Get TTL for user data"""
        ttl_mapping = {
            'profile': 7200,      # 2 hours
            'permissions': 14400, # 4 hours
            'dashboard': 1800     # 30 minutes
        }
        return ttl_mapping.get(self.data_type, 3600)


class CacheWarmingManager:
    """
    Advanced cache warming system with predictive caching
    Task 4.1.3: Core warming functionality
    """
    
    def __init__(self, max_workers: int = 8, max_queue_size: int = 10000):
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        
        # Job queues by priority
        self.critical_queue = deque(maxlen=max_queue_size // 4)
        self.high_queue = deque(maxlen=max_queue_size // 4)
        self.normal_queue = deque(maxlen=max_queue_size // 4)
        self.low_queue = deque(maxlen=max_queue_size // 4)
        
        # Metrics and tracking
        self.metrics = WarmingMetrics()
        self.warming_jobs = {}  # key -> WarmingJob
        self.warming_history = deque(maxlen=1000)
        
        # Threading
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='cache_warming')
        
        # Configuration
        self.warming_enabled = True
        self.predictive_warming_enabled = True
        self.background_refresh_enabled = True
        
        # Access pattern tracking for predictive warming
        self.access_patterns = defaultdict(list)  # key -> [access_times]
        self.pattern_window = timedelta(hours=24)
        
        # Start background processes
        self._start_background_warmer()
        self._start_access_pattern_analyzer()
    
    def register_warming_job(
        self,
        key: str,
        data_source: Union[Callable[[], Any], CacheDataSource],
        priority: int = 3,
        ttl: Optional[int] = None,
        dependencies: Optional[List[str]] = None,
        organization_id: Optional[int] = None,
        category: str = "general"
    ) -> str:
        """
        Register a cache warming job
        Task 4.1.3: Job registration system
        """
        
        # Handle data source
        if isinstance(data_source, CacheDataSource):
            data_func = data_source.get_data
            ttl = ttl or data_source.get_ttl()
            dependencies = dependencies or data_source.get_dependencies()
        else:
            data_func = data_source
            ttl = ttl or 3600
            dependencies = dependencies or []
        
        job = WarmingJob(
            key=key,
            data_source=data_func,
            priority=priority,
            ttl=ttl,
            dependencies=dependencies,
            organization_id=organization_id,
            category=category
        )
        
        with self.lock:
            self.warming_jobs[key] = job
        
        job_id = self._generate_job_id(key)
        logger.info(f"Registered cache warming job {job_id} for key: {key}")
        
        return job_id
    
    def warm_cache_key(self, key: str, immediate: bool = False) -> Dict[str, Any]:
        """
        Warm a specific cache key
        Task 4.1.3: Individual key warming
        """
        
        start_time = time.time()
        
        try:
            job = self.warming_jobs.get(key)
            if not job:
                return {
                    'success': False,
                    'error': f'No warming job registered for key: {key}',
                    'execution_time': time.time() - start_time
                }
            
            if immediate:
                return self._execute_warming_job(job)
            else:
                # Queue for background processing
                self._queue_warming_job(job)
                return {
                    'success': True,
                    'queued': True,
                    'message': f'Warming job queued for key: {key}',
                    'execution_time': time.time() - start_time
                }
                
        except Exception as e:
            logger.error(f"Error warming cache key {key}: {e}")
            return {
                'success': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def warm_organization_cache(self, organization_id: int, data_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Warm cache for an entire organization
        Task 4.1.3: Organization-wide warming
        """
        
        start_time = time.time()
        data_types = data_types or ['dashboard_stats', 'deal_list', 'client_list', 'team_info']
        
        try:
            warming_results = []
            
            for data_type in data_types:
                key = f"org_{organization_id}_{data_type}"
                
                # Create data source
                data_source = OrganizationDataSource(organization_id, data_type)
                
                # Register and warm immediately
                self.register_warming_job(
                    key=key,
                    data_source=data_source,
                    priority=1,  # High priority for organization warming
                    organization_id=organization_id,
                    category='organization'
                )
                
                result = self.warm_cache_key(key, immediate=True)
                warming_results.append({
                    'key': key,
                    'result': result
                })
            
            # Summary
            successful = sum(1 for r in warming_results if r['result']['success'])
            total = len(warming_results)
            
            return {
                'success': successful > 0,
                'organization_id': organization_id,
                'total_keys': total,
                'successful_keys': successful,
                'failed_keys': total - successful,
                'results': warming_results,
                'execution_time': time.time() - start_time
            }
            
        except Exception as e:
            logger.error(f"Error warming organization {organization_id} cache: {e}")
            return {
                'success': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def warm_user_cache(self, user_id: int, data_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Warm cache for a specific user
        Task 4.1.3: User-specific warming
        """
        
        start_time = time.time()
        data_types = data_types or ['profile', 'permissions', 'dashboard']
        
        try:
            warming_results = []
            
            for data_type in data_types:
                key = f"user_{user_id}_{data_type}"
                
                # Create data source
                data_source = UserDataSource(user_id, data_type)
                
                # Register and warm immediately
                self.register_warming_job(
                    key=key,
                    data_source=data_source,
                    priority=2,  # High priority for user warming
                    category='user'
                )
                
                result = self.warm_cache_key(key, immediate=True)
                warming_results.append({
                    'key': key,
                    'result': result
                })
            
            # Summary
            successful = sum(1 for r in warming_results if r['result']['success'])
            total = len(warming_results)
            
            return {
                'success': successful > 0,
                'user_id': user_id,
                'total_keys': total,
                'successful_keys': successful,
                'failed_keys': total - successful,
                'results': warming_results,
                'execution_time': time.time() - start_time
            }
            
        except Exception as e:
            logger.error(f"Error warming user {user_id} cache: {e}")
            return {
                'success': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def warm_critical_cache(self) -> Dict[str, Any]:
        """
        Warm all critical cache entries
        Task 4.1.3: Critical data warming
        """
        
        start_time = time.time()
        
        try:
            critical_jobs = []
            
            with self.lock:
                for job in self.warming_jobs.values():
                    if job.priority == 1:  # Critical priority
                        critical_jobs.append(job)
            
            if not critical_jobs:
                return {
                    'success': True,
                    'message': 'No critical cache jobs to warm',
                    'execution_time': time.time() - start_time
                }
            
            # Execute critical jobs in parallel
            results = []
            with ThreadPoolExecutor(max_workers=min(len(critical_jobs), self.max_workers)) as executor:
                future_to_job = {
                    executor.submit(self._execute_warming_job, job): job
                    for job in critical_jobs
                }
                
                for future in as_completed(future_to_job):
                    job = future_to_job[future]
                    try:
                        result = future.result()
                        results.append({
                            'key': job.key,
                            'result': result
                        })
                    except Exception as e:
                        logger.error(f"Critical warming job failed for {job.key}: {e}")
                        results.append({
                            'key': job.key,
                            'result': {
                                'success': False,
                                'error': str(e)
                            }
                        })
            
            # Summary
            successful = sum(1 for r in results if r['result']['success'])
            total = len(results)
            
            return {
                'success': successful > 0,
                'total_jobs': total,
                'successful_jobs': successful,
                'failed_jobs': total - successful,
                'results': results,
                'execution_time': time.time() - start_time
            }
            
        except Exception as e:
            logger.error(f"Error warming critical cache: {e}")
            return {
                'success': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def enable_predictive_warming(self, access_threshold: int = 3, prediction_window_hours: int = 2):
        """
        Enable predictive cache warming based on access patterns
        Task 4.1.3: Predictive warming
        """
        
        self.predictive_warming_enabled = True
        self.access_threshold = access_threshold
        self.prediction_window = timedelta(hours=prediction_window_hours)
        
        logger.info(f"Predictive warming enabled: threshold={access_threshold}, window={prediction_window_hours}h")
    
    def track_cache_access(self, key: str):
        """
        Track cache access for predictive warming
        Task 4.1.3: Access pattern tracking
        """
        
        if not self.predictive_warming_enabled:
            return
        
        now = timezone.now()
        
        with self.lock:
            # Clean old access records
            cutoff_time = now - self.pattern_window
            self.access_patterns[key] = [
                access_time for access_time in self.access_patterns[key]
                if access_time > cutoff_time
            ]
            
            # Add new access
            self.access_patterns[key].append(now)
            
            # Trigger predictive warming if threshold met
            if len(self.access_patterns[key]) >= self.access_threshold:
                self._schedule_predictive_warming(key)
    
    def _execute_warming_job(self, job: WarmingJob) -> Dict[str, Any]:
        """Execute a cache warming job"""
        
        start_time = time.time()
        
        try:
            # Check if key already exists and is fresh
            existing_data = cache.get(job.key)
            if existing_data and not self._should_refresh(job):
                return {
                    'success': True,
                    'cached': True,
                    'message': f'Key {job.key} already cached and fresh',
                    'execution_time': time.time() - start_time
                }
            
            # Get fresh data
            data = job.data_source()
            
            if data is None:
                raise ValueError("Data source returned None")
            
            # Cache the data
            cache.set(job.key, data, job.ttl)
            
            # Update job metrics
            with self.lock:
                job.last_warmed = timezone.now()
                job.success_count += 1
                
                # Update global metrics
                self.metrics.successful_warmings += 1
                self.metrics.total_warming_jobs += 1
                
                # Estimate data size
                data_size = len(str(data).encode('utf-8'))
                self.metrics.total_data_warmed += data_size
                
                # Update average time
                execution_time = time.time() - start_time
                self.metrics.avg_warming_time = (
                    (self.metrics.avg_warming_time * (self.metrics.successful_warmings - 1) + execution_time)
                    / self.metrics.successful_warmings
                )
            
            logger.info(f"Successfully warmed cache key: {job.key}")
            
            return {
                'success': True,
                'key': job.key,
                'data_size': data_size,
                'ttl': job.ttl,
                'execution_time': execution_time
            }
            
        except Exception as e:
            logger.error(f"Failed to warm cache key {job.key}: {e}")
            
            with self.lock:
                job.failure_count += 1
                self.metrics.failed_warmings += 1
                self.metrics.total_warming_jobs += 1
            
            return {
                'success': False,
                'key': job.key,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def _should_refresh(self, job: WarmingJob) -> bool:
        """Check if a job should be refreshed"""
        
        if not job.last_warmed:
            return True
        
        # Refresh if more than 75% of TTL has passed
        refresh_threshold = job.ttl * 0.75
        time_since_warmed = (timezone.now() - job.last_warmed).total_seconds()
        
        return time_since_warmed >= refresh_threshold
    
    def _queue_warming_job(self, job: WarmingJob):
        """Queue a warming job based on priority"""
        
        with self.lock:
            if job.priority == 1:
                self.critical_queue.append(job)
            elif job.priority == 2:
                self.high_queue.append(job)
            elif job.priority == 3:
                self.normal_queue.append(job)
            else:
                self.low_queue.append(job)
    
    def _get_next_warming_job(self) -> Optional[WarmingJob]:
        """Get next warming job from priority queues"""
        
        with self.lock:
            # Process by priority
            for queue in [self.critical_queue, self.high_queue, self.normal_queue, self.low_queue]:
                if queue:
                    return queue.popleft()
        
        return None
    
    def _start_background_warmer(self):
        """Start background cache warming process"""
        
        def warming_worker():
            while True:
                try:
                    if not self.warming_enabled:
                        time.sleep(5)
                        continue
                    
                    job = self._get_next_warming_job()
                    if job:
                        self._execute_warming_job(job)
                    else:
                        time.sleep(1)  # Wait if no jobs
                        
                except Exception as e:
                    logger.error(f"Background warming error: {e}")
                    time.sleep(5)
        
        # Start background thread
        thread = threading.Thread(target=warming_worker, daemon=True, name='cache_warming_worker')
        thread.start()
        
        logger.info("Background cache warming started")
    
    def _start_access_pattern_analyzer(self):
        """Start access pattern analysis for predictive warming"""
        
        def pattern_analyzer():
            while True:
                try:
                    if not self.predictive_warming_enabled:
                        time.sleep(60)
                        continue
                    
                    self._analyze_access_patterns()
                    time.sleep(300)  # Analyze every 5 minutes
                    
                except Exception as e:
                    logger.error(f"Access pattern analysis error: {e}")
                    time.sleep(60)
        
        # Start background thread
        thread = threading.Thread(target=pattern_analyzer, daemon=True, name='access_pattern_analyzer')
        thread.start()
        
        logger.info("Access pattern analyzer started")
    
    def _analyze_access_patterns(self):
        """Analyze access patterns and schedule predictive warming"""
        
        now = timezone.now()
        cutoff_time = now - self.pattern_window
        
        with self.lock:
            for key, access_times in list(self.access_patterns.items()):
                # Clean old records
                recent_accesses = [t for t in access_times if t > cutoff_time]
                self.access_patterns[key] = recent_accesses
                
                # Predict future access and warm if needed
                if len(recent_accesses) >= self.access_threshold:
                    self._schedule_predictive_warming(key)
    
    def _schedule_predictive_warming(self, key: str):
        """Schedule predictive warming for a key"""
        
        # Check if we have a job for this key
        if key in self.warming_jobs:
            job = self.warming_jobs[key]
            
            # Check if it needs refreshing
            if self._should_refresh(job):
                self._queue_warming_job(job)
                
                with self.lock:
                    self.metrics.predictive_hits += 1
                
                logger.info(f"Scheduled predictive warming for key: {key}")
    
    def _generate_job_id(self, key: str) -> str:
        """Generate unique job ID"""
        return hashlib.md5(f"{key}{timezone.now().isoformat()}".encode()).hexdigest()[:8]
    
    def get_warming_metrics(self) -> WarmingMetrics:
        """Get current warming metrics"""
        
        with self.lock:
            return WarmingMetrics(
                total_warming_jobs=self.metrics.total_warming_jobs,
                successful_warmings=self.metrics.successful_warmings,
                failed_warmings=self.metrics.failed_warmings,
                avg_warming_time=self.metrics.avg_warming_time,
                total_data_warmed=self.metrics.total_data_warmed,
                cache_hit_improvement=self.metrics.cache_hit_improvement,
                predictive_hits=self.metrics.predictive_hits
            )
    
    def get_warming_status(self) -> Dict[str, Any]:
        """Get current warming system status"""
        
        with self.lock:
            queue_sizes = {
                'critical': len(self.critical_queue),
                'high': len(self.high_queue),
                'normal': len(self.normal_queue),
                'low': len(self.low_queue)
            }
            
            total_jobs = len(self.warming_jobs)
            active_jobs = sum(1 for job in self.warming_jobs.values() if job.last_warmed)
            
        return {
            'warming_enabled': self.warming_enabled,
            'predictive_warming_enabled': self.predictive_warming_enabled,
            'background_refresh_enabled': self.background_refresh_enabled,
            'total_registered_jobs': total_jobs,
            'active_jobs': active_jobs,
            'queue_sizes': queue_sizes,
            'total_queued': sum(queue_sizes.values()),
            'access_patterns_tracked': len(self.access_patterns),
            'metrics': self.get_warming_metrics()
        }


# Global cache warming manager instance
cache_warming_manager = CacheWarmingManager()


# Utility functions for common warming scenarios
def warm_organization_data(organization_id: int) -> Dict[str, Any]:
    """Convenience function to warm organization data"""
    return cache_warming_manager.warm_organization_cache(organization_id)


def warm_user_data(user_id: int) -> Dict[str, Any]:
    """Convenience function to warm user data"""
    return cache_warming_manager.warm_user_cache(user_id)


def warm_critical_data() -> Dict[str, Any]:
    """Convenience function to warm all critical data"""
    return cache_warming_manager.warm_critical_cache()


# Django integration for automatic warming
def auto_warm_on_login(user):
    """Auto-warm user cache on login"""
    try:
        cache_warming_manager.warm_user_cache(user.id)
        
        # Also warm organization data if available
        if hasattr(user, 'organization') and user.organization:
            cache_warming_manager.warm_organization_cache(user.organization.id, ['dashboard_stats'])
            
    except Exception as e:
        logger.error(f"Error auto-warming cache on login for user {user.id}: {e}")


def register_common_warming_jobs():
    """Register common cache warming jobs for the PRS system"""
    
    # This would be called during Django startup to register common jobs
    logger.info("Registering common cache warming jobs...")
    
    # Example registrations (these would be customized for your specific cache keys)
    cache_warming_manager.register_warming_job(
        key="system_stats",
        data_source=lambda: {"total_users": 1000, "total_deals": 5000},  # Replace with actual data
        priority=1,
        ttl=1800,
        category="system"
    )
    
    logger.info("Common cache warming jobs registered")
