"""
Error correlation and tracking system for PRS Backend
Provides comprehensive error tracking, correlation, and pattern analysis
"""

import json
import time
import hashlib
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from threading import Lock
import redis
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache

from .structured_logger import StructuredLogger, EventType, LogLevel


@dataclass
class ErrorSignature:
    """Unique signature for error identification and correlation"""
    error_type: str
    error_location: str  # module.function
    error_pattern: str   # Normalized error message pattern
    
    def __post_init__(self):
        self.signature_hash = hashlib.md5(
            f"{self.error_type}:{self.error_location}:{self.error_pattern}".encode()
        ).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorOccurrence:
    """Individual error occurrence with context"""
    timestamp: str
    correlation_id: str
    user_id: Optional[int]
    organization_id: Optional[int]
    request_path: str
    request_method: str
    ip_address: str
    error_message: str
    stack_trace: Optional[str] = None
    context_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorCluster:
    """Clustered errors with common signature"""
    signature: ErrorSignature
    first_occurrence: str
    last_occurrence: str
    occurrence_count: int
    unique_users: Set[int]
    unique_ips: Set[str]
    occurrences: List[ErrorOccurrence]
    severity_level: str
    status: str = 'active'  # active, resolved, investigating
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['unique_users'] = list(self.unique_users)
        data['unique_ips'] = list(self.unique_ips)
        data['signature'] = self.signature.to_dict()
        data['occurrences'] = [occ.to_dict() for occ in self.occurrences[-10:]]  # Last 10 occurrences
        return data


class ErrorPattern:
    """Patterns for error message normalization"""
    
    COMMON_PATTERNS = [
        # Database errors
        (r'duplicate key value violates unique constraint ".*"', 'duplicate_key_constraint'),
        (r'relation ".*" does not exist', 'table_not_found'),
        (r'column ".*" does not exist', 'column_not_found'),
        (r'could not connect to server: Connection refused', 'database_connection_refused'),
        (r'server closed the connection unexpectedly', 'database_connection_lost'),
        
        # Authentication errors
        (r'Invalid token.*', 'invalid_token'),
        (r'Token has expired.*', 'token_expired'),
        (r'User matching query does not exist', 'user_not_found'),
        (r'Incorrect authentication credentials', 'invalid_credentials'),
        
        # Validation errors
        (r'This field is required.*', 'required_field_missing'),
        (r'Enter a valid email address.*', 'invalid_email_format'),
        (r'Ensure this value has at most \d+ characters.*', 'field_too_long'),
        (r'Invalid pk ".*" - object does not exist.*', 'invalid_primary_key'),
        
        # File/Upload errors
        (r'File size too large.*', 'file_too_large'),
        (r'Invalid file type.*', 'invalid_file_type'),
        (r'Upload failed.*', 'upload_failed'),
        
        # External API errors
        (r'Connection timeout.*', 'connection_timeout'),
        (r'HTTP \d{3} Error.*', 'http_error'),
        (r'SSL certificate verify failed.*', 'ssl_verification_failed'),
        
        # Memory/Resource errors
        (r'Out of memory.*', 'out_of_memory'),
        (r'Disk full.*', 'disk_full'),
        (r'Too many open files.*', 'too_many_files'),
    ]
    
    @classmethod
    def normalize_error_message(cls, error_message: str) -> str:
        """Normalize error message to identify patterns"""
        import re
        
        for pattern, normalized in cls.COMMON_PATTERNS:
            if re.search(pattern, error_message, re.IGNORECASE):
                return normalized
        
        # Generic normalization
        # Remove specific values but keep structure
        normalized = error_message
        
        # Replace numbers with placeholder
        normalized = re.sub(r'\d+', 'N', normalized)
        
        # Replace UUIDs with placeholder
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', normalized, flags=re.IGNORECASE)
        
        # Replace file paths with placeholder
        normalized = re.sub(r'/[a-zA-Z0-9_\-./]*', 'PATH', normalized)
        
        # Replace email addresses with placeholder
        normalized = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL', normalized)
        
        return normalized[:200]  # Limit length


class ErrorCorrelationTracker:
    """Central error correlation and tracking system"""
    
    def __init__(self):
        self.logger = StructuredLogger('error_correlation')
        self.error_clusters: Dict[str, ErrorCluster] = {}
        self.recent_errors = deque(maxlen=1000)  # Keep last 1000 errors in memory
        self._lock = Lock()
        
        # Redis connection for distributed tracking
        try:
            self.redis_client = redis.Redis.from_url(settings.REDIS_URL) if hasattr(settings, 'REDIS_URL') else None
        except:
            self.redis_client = None
            self.logger.warning(EventType.SYSTEM_ERROR, "Redis connection failed for error correlation")
    
    def track_error(self, error: Exception, correlation_id: str = None,
                   user_id: int = None, organization_id: int = None,
                   request_path: str = None, request_method: str = None,
                   ip_address: str = None, context_data: Dict[str, Any] = None):
        """Track an error occurrence with correlation"""
        
        try:
            # Create error signature
            signature = self._create_error_signature(error)
            
            # Create error occurrence
            occurrence = ErrorOccurrence(
                timestamp=timezone.now().isoformat(),
                correlation_id=correlation_id or 'unknown',
                user_id=user_id,
                organization_id=organization_id,
                request_path=request_path or 'unknown',
                request_method=request_method or 'unknown',
                ip_address=ip_address or 'unknown',
                error_message=str(error),
                stack_trace=self._get_stack_trace(error),
                context_data=context_data or {}
            )
            
            # Update or create error cluster
            with self._lock:
                cluster = self._update_error_cluster(signature, occurrence)
                
                # Add to recent errors
                self.recent_errors.append(occurrence)
                
                # Persist to Redis if available
                if self.redis_client:
                    self._persist_error_cluster(cluster)
                
                # Check for error patterns and alerts
                self._check_error_patterns(cluster)
            
            # Log the error correlation
            self.logger.error(
                EventType.SYSTEM_ERROR,
                f"Error tracked: {signature.error_type} in {signature.error_location}",
                extra_data={
                    'signature_hash': signature.signature_hash,
                    'occurrence_count': cluster.occurrence_count,
                    'unique_users': len(cluster.unique_users),
                    'first_occurrence': cluster.first_occurrence,
                    'pattern': signature.error_pattern
                },
                tags=['error_correlation', signature.error_type.lower()]
            )
            
            return cluster
            
        except Exception as tracking_error:
            # Don't let error tracking itself cause issues
            self.logger.critical(
                EventType.SYSTEM_ERROR,
                "Failed to track error in correlation system",
                exception=tracking_error
            )
            return None
    
    def _create_error_signature(self, error: Exception) -> ErrorSignature:
        """Create unique signature for error"""
        import traceback
        
        # Get error location from stack trace
        tb = traceback.extract_tb(error.__traceback__)
        if tb:
            # Get the last frame that's not in the error tracking system
            for frame in reversed(tb):
                if 'error_correlation' not in frame.filename and 'structured_logger' not in frame.filename:
                    error_location = f"{frame.filename.split('/')[-1]}:{frame.name}"
                    break
            else:
                error_location = f"{tb[-1].filename.split('/')[-1]}:{tb[-1].name}"
        else:
            error_location = "unknown:unknown"
        
        # Normalize error message for pattern matching
        error_pattern = ErrorPattern.normalize_error_message(str(error))
        
        return ErrorSignature(
            error_type=type(error).__name__,
            error_location=error_location,
            error_pattern=error_pattern
        )
    
    def _get_stack_trace(self, error: Exception) -> str:
        """Get formatted stack trace"""
        import traceback
        
        try:
            return ''.join(traceback.format_exception(type(error), error, error.__traceback__))
        except:
            return f"Could not format stack trace for {type(error).__name__}: {str(error)}"
    
    def _update_error_cluster(self, signature: ErrorSignature, occurrence: ErrorOccurrence) -> ErrorCluster:
        """Update or create error cluster"""
        
        cluster_key = signature.signature_hash
        
        if cluster_key in self.error_clusters:
            cluster = self.error_clusters[cluster_key]
            cluster.last_occurrence = occurrence.timestamp
            cluster.occurrence_count += 1
            
            if occurrence.user_id:
                cluster.unique_users.add(occurrence.user_id)
            if occurrence.ip_address != 'unknown':
                cluster.unique_ips.add(occurrence.ip_address)
            
            cluster.occurrences.append(occurrence)
            
            # Keep only recent occurrences in memory
            if len(cluster.occurrences) > 50:
                cluster.occurrences = cluster.occurrences[-25:]
        
        else:
            # Create new cluster
            cluster = ErrorCluster(
                signature=signature,
                first_occurrence=occurrence.timestamp,
                last_occurrence=occurrence.timestamp,
                occurrence_count=1,
                unique_users={occurrence.user_id} if occurrence.user_id else set(),
                unique_ips={occurrence.ip_address} if occurrence.ip_address != 'unknown' else set(),
                occurrences=[occurrence],
                severity_level=self._calculate_severity(signature, occurrence)
            )
            
            self.error_clusters[cluster_key] = cluster
        
        return cluster
    
    def _calculate_severity(self, signature: ErrorSignature, occurrence: ErrorOccurrence) -> str:
        """Calculate error severity based on type and context"""
        
        # Critical errors
        critical_patterns = [
            'database_connection_refused',
            'out_of_memory',
            'disk_full',
            'ssl_verification_failed'
        ]
        
        if signature.error_pattern in critical_patterns or signature.error_type in ['SystemExit', 'MemoryError']:
            return 'critical'
        
        # High severity errors
        high_patterns = [
            'database_connection_lost',
            'table_not_found',
            'invalid_token',
            'user_not_found'
        ]
        
        if signature.error_pattern in high_patterns or signature.error_type in ['DatabaseError', 'AuthenticationError']:
            return 'high'
        
        # Medium severity errors
        medium_patterns = [
            'duplicate_key_constraint',
            'column_not_found',
            'invalid_credentials',
            'file_too_large'
        ]
        
        if signature.error_pattern in medium_patterns or signature.error_type in ['ValidationError', 'PermissionError']:
            return 'medium'
        
        # Default to low severity
        return 'low'
    
    def _persist_error_cluster(self, cluster: ErrorCluster):
        """Persist error cluster to Redis"""
        if not self.redis_client:
            return
        
        try:
            key = f"error_cluster:{cluster.signature.signature_hash}"
            data = cluster.to_dict()
            
            # Store with 30-day expiration
            self.redis_client.setex(key, 30 * 24 * 3600, json.dumps(data, default=str))
            
            # Add to error patterns index
            pattern_key = f"error_pattern:{cluster.signature.error_pattern}"
            self.redis_client.sadd(pattern_key, cluster.signature.signature_hash)
            self.redis_client.expire(pattern_key, 30 * 24 * 3600)
            
        except Exception as e:
            self.logger.warning(
                EventType.SYSTEM_ERROR,
                "Failed to persist error cluster to Redis",
                exception=e
            )
    
    def _check_error_patterns(self, cluster: ErrorCluster):
        """Check for concerning error patterns and trigger alerts"""
        
        # Check for error spikes
        recent_count = sum(1 for occ in cluster.occurrences 
                         if datetime.fromisoformat(occ.timestamp.replace('Z', '+00:00')) 
                         > datetime.now(timezone.utc) - timedelta(minutes=5))
        
        if recent_count >= 10:
            self._trigger_error_spike_alert(cluster, recent_count)
        
        # Check for new error patterns
        if cluster.occurrence_count == 1:
            self._trigger_new_error_alert(cluster)
        
        # Check for critical error patterns
        if cluster.severity_level == 'critical' and cluster.occurrence_count >= 3:
            self._trigger_critical_error_alert(cluster)
        
        # Check for widespread impact
        if len(cluster.unique_users) >= 10 or len(cluster.unique_ips) >= 20:
            self._trigger_widespread_impact_alert(cluster)
    
    def _trigger_error_spike_alert(self, cluster: ErrorCluster, recent_count: int):
        """Trigger alert for error spike"""
        self.logger.critical(
            EventType.SYSTEM_ERROR,
            f"Error spike detected: {cluster.signature.error_type} ({recent_count} occurrences in 5 minutes)",
            extra_data={
                'signature_hash': cluster.signature.signature_hash,
                'recent_count': recent_count,
                'total_count': cluster.occurrence_count,
                'affected_users': len(cluster.unique_users),
                'pattern': cluster.signature.error_pattern
            },
            tags=['alert', 'error_spike', 'critical']
        )
    
    def _trigger_new_error_alert(self, cluster: ErrorCluster):
        """Trigger alert for new error pattern"""
        self.logger.warning(
            EventType.SYSTEM_ERROR,
            f"New error pattern detected: {cluster.signature.error_type} in {cluster.signature.error_location}",
            extra_data={
                'signature_hash': cluster.signature.signature_hash,
                'pattern': cluster.signature.error_pattern,
                'severity': cluster.severity_level
            },
            tags=['alert', 'new_error', cluster.severity_level]
        )
    
    def _trigger_critical_error_alert(self, cluster: ErrorCluster):
        """Trigger alert for critical errors"""
        self.logger.critical(
            EventType.SYSTEM_ERROR,
            f"Critical error pattern: {cluster.signature.error_type} (occurred {cluster.occurrence_count} times)",
            extra_data={
                'signature_hash': cluster.signature.signature_hash,
                'occurrence_count': cluster.occurrence_count,
                'affected_users': len(cluster.unique_users),
                'first_occurrence': cluster.first_occurrence,
                'pattern': cluster.signature.error_pattern
            },
            tags=['alert', 'critical_error', 'critical']
        )
    
    def _trigger_widespread_impact_alert(self, cluster: ErrorCluster):
        """Trigger alert for widespread error impact"""
        self.logger.critical(
            EventType.SYSTEM_ERROR,
            f"Widespread error impact: {cluster.signature.error_type} affecting {len(cluster.unique_users)} users",
            extra_data={
                'signature_hash': cluster.signature.signature_hash,
                'affected_users': len(cluster.unique_users),
                'affected_ips': len(cluster.unique_ips),
                'occurrence_count': cluster.occurrence_count,
                'pattern': cluster.signature.error_pattern
            },
            tags=['alert', 'widespread_impact', 'critical']
        )
    
    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get error summary for the last N hours"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        
        summary = {
            'total_clusters': len(self.error_clusters),
            'active_clusters': 0,
            'total_occurrences': 0,
            'severity_breakdown': defaultdict(int),
            'top_errors': [],
            'new_errors': [],
            'critical_errors': []
        }
        
        for cluster in self.error_clusters.values():
            last_occurrence_time = datetime.fromisoformat(cluster.last_occurrence.replace('Z', '+00:00'))
            
            if last_occurrence_time > cutoff_time:
                summary['active_clusters'] += 1
                summary['total_occurrences'] += cluster.occurrence_count
                summary['severity_breakdown'][cluster.severity_level] += 1
                
                cluster_info = {
                    'signature_hash': cluster.signature.signature_hash,
                    'error_type': cluster.signature.error_type,
                    'error_location': cluster.signature.error_location,
                    'occurrence_count': cluster.occurrence_count,
                    'affected_users': len(cluster.unique_users),
                    'severity': cluster.severity_level,
                    'last_occurrence': cluster.last_occurrence
                }
                
                # Add to appropriate categories
                if cluster.occurrence_count == 1:
                    summary['new_errors'].append(cluster_info)
                
                if cluster.severity_level == 'critical':
                    summary['critical_errors'].append(cluster_info)
                
                summary['top_errors'].append(cluster_info)
        
        # Sort and limit results
        summary['top_errors'] = sorted(summary['top_errors'], key=lambda x: x['occurrence_count'], reverse=True)[:10]
        summary['new_errors'] = sorted(summary['new_errors'], key=lambda x: x['last_occurrence'], reverse=True)[:10]
        summary['critical_errors'] = sorted(summary['critical_errors'], key=lambda x: x['occurrence_count'], reverse=True)[:10]
        summary['severity_breakdown'] = dict(summary['severity_breakdown'])
        
        return summary
    
    def get_error_cluster(self, signature_hash: str) -> Optional[ErrorCluster]:
        """Get specific error cluster by signature hash"""
        return self.error_clusters.get(signature_hash)
    
    def get_related_errors(self, signature_hash: str) -> List[ErrorCluster]:
        """Get errors related to the given error"""
        target_cluster = self.error_clusters.get(signature_hash)
        if not target_cluster:
            return []
        
        related = []
        target_pattern = target_cluster.signature.error_pattern
        target_location = target_cluster.signature.error_location
        
        for cluster in self.error_clusters.values():
            if cluster.signature.signature_hash == signature_hash:
                continue
                
            # Same error pattern in different location
            if cluster.signature.error_pattern == target_pattern:
                related.append(cluster)
                continue
            
            # Same location with different error
            if cluster.signature.error_location == target_location:
                related.append(cluster)
                continue
        
        return sorted(related, key=lambda x: x.occurrence_count, reverse=True)[:5]
    
    def mark_cluster_resolved(self, signature_hash: str, resolved_by: str = None):
        """Mark an error cluster as resolved"""
        if signature_hash in self.error_clusters:
            cluster = self.error_clusters[signature_hash]
            cluster.status = 'resolved'
            
            self.logger.info(
                EventType.SYSTEM_ERROR,
                f"Error cluster marked as resolved: {cluster.signature.error_type}",
                extra_data={
                    'signature_hash': signature_hash,
                    'resolved_by': resolved_by,
                    'total_occurrences': cluster.occurrence_count
                },
                tags=['resolved', 'error_management']
            )
            
            if self.redis_client:
                self._persist_error_cluster(cluster)
    
    def cleanup_old_errors(self, days: int = 30):
        """Clean up error clusters older than specified days"""
        cutoff_time = timezone.now() - timedelta(days=days)
        
        clusters_to_remove = []
        for signature_hash, cluster in self.error_clusters.items():
            last_occurrence_time = datetime.fromisoformat(cluster.last_occurrence.replace('Z', '+00:00'))
            
            if last_occurrence_time < cutoff_time:
                clusters_to_remove.append(signature_hash)
        
        for signature_hash in clusters_to_remove:
            del self.error_clusters[signature_hash]
            
            # Remove from Redis
            if self.redis_client:
                try:
                    self.redis_client.delete(f"error_cluster:{signature_hash}")
                except Exception as e:
                    self.logger.warning(
                        EventType.SYSTEM_ERROR,
                        "Failed to remove old error cluster from Redis",
                        exception=e
                    )
        
        if clusters_to_remove:
            self.logger.info(
                EventType.SYSTEM_ERROR,
                f"Cleaned up {len(clusters_to_remove)} old error clusters",
                extra_data={'cleaned_clusters': len(clusters_to_remove), 'cutoff_days': days},
                tags=['cleanup', 'maintenance']
            )


# Global error correlation tracker
error_tracker = ErrorCorrelationTracker()


def track_error(error: Exception, **context):
    """Convenience function to track an error"""
    return error_tracker.track_error(error, **context)


def get_error_summary(hours: int = 24) -> Dict[str, Any]:
    """Get error summary for the last N hours"""
    return error_tracker.get_error_summary(hours)


def get_error_cluster(signature_hash: str) -> Optional[ErrorCluster]:
    """Get specific error cluster"""
    return error_tracker.get_error_cluster(signature_hash)
