"""
Enhanced Error Handling Workflows for PRS Backend
Provides graceful recovery, user-friendly messages, and escalation procedures
"""

import time
import asyncio
from typing import Dict, Any, Optional, Callable, List, Union, Type
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
from contextlib import contextmanager

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction, DatabaseError, OperationalError, IntegrityError
from django.core.cache import cache
from django.http import JsonResponse
from rest_framework.exceptions import APIException
from rest_framework import status

from ..logging import StructuredLogger, EventType, track_error, log_business_event


class RecoveryStrategy(Enum):
    """Recovery strategies for different error types"""
    IMMEDIATE_RETRY = "immediate_retry"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    FALLBACK_SERVICE = "fallback_service" 
    GRACEFUL_DEGRADATION = "graceful_degradation"
    USER_INTERVENTION = "user_intervention"
    ESCALATE_TO_ADMIN = "escalate_to_admin"
    FAIL_SAFE = "fail_safe"


class ErrorSeverity(Enum):
    """Error severity levels with escalation rules"""
    LOW = ("low", 1, False)
    MEDIUM = ("medium", 2, False)
    HIGH = ("high", 3, True)
    CRITICAL = ("critical", 4, True)
    
    def __init__(self, level: str, priority: int, requires_escalation: bool):
        self.level = level
        self.priority = priority
        self.requires_escalation = requires_escalation


@dataclass
class RecoveryResult:
    """Result of error recovery attempt"""
    success: bool
    strategy_used: RecoveryStrategy
    attempts: int
    duration_ms: float
    fallback_used: bool = False
    user_message: Optional[str] = None
    admin_message: Optional[str] = None
    next_action: Optional[str] = None


@dataclass 
class UserFriendlyError:
    """User-friendly error representation"""
    title: str
    message: str
    suggestions: List[str]
    help_url: Optional[str] = None
    contact_support: bool = False
    retry_allowed: bool = True
    severity: ErrorSeverity = ErrorSeverity.MEDIUM


class EnhancedErrorHandler:
    """
    Enhanced error handler with recovery strategies and user-friendly messages
    """
    
    def __init__(self):
        self.logger = StructuredLogger('error_handler')
        self.recovery_strategies = self._initialize_recovery_strategies()
        self.error_mappings = self._initialize_error_mappings()
        self.escalation_rules = self._initialize_escalation_rules()
    
    def handle_error(self, error: Exception, context: Dict[str, Any] = None,
                    user_id: int = None, request_id: str = None) -> Dict[str, Any]:
        """
        Main error handling entry point with recovery and user messaging
        """
        start_time = time.time()
        context = context or {}
        
        # Track the error for correlation
        error_cluster = track_error(
            error=error,
            correlation_id=request_id,
            user_id=user_id,
            context_data=context
        )
        
        # Determine error type and appropriate handling
        error_type = self._classify_error(error)
        severity = self._determine_severity(error, error_cluster)
        
        # Attempt recovery
        recovery_result = self._attempt_recovery(error, error_type, context)
        
        # Generate user-friendly error representation
        user_error = self._create_user_friendly_error(error, error_type, severity, recovery_result)
        
        # Check if escalation is needed
        escalation_result = self._check_escalation(error, severity, error_cluster, recovery_result)
        
        # Log the handling process
        processing_time = (time.time() - start_time) * 1000
        self._log_error_handling(
            error=error,
            error_type=error_type,
            severity=severity,
            recovery_result=recovery_result,
            user_error=user_error,
            escalation_result=escalation_result,
            processing_time=processing_time,
            context=context
        )
        
        # Return comprehensive error response
        return {
            'error': {
                'type': error_type,
                'severity': severity.level,
                'title': user_error.title,
                'message': user_error.message,
                'suggestions': user_error.suggestions,
                'help_url': user_error.help_url,
                'contact_support': user_error.contact_support,
                'retry_allowed': user_error.retry_allowed,
            },
            'recovery': {
                'attempted': recovery_result.success if recovery_result else False,
                'strategy': recovery_result.strategy_used.value if recovery_result else None,
                'fallback_available': recovery_result.fallback_used if recovery_result else False,
                'next_action': recovery_result.next_action if recovery_result else None,
            },
            'meta': {
                'request_id': request_id,
                'timestamp': datetime.utcnow().isoformat(),
                'processing_time_ms': processing_time,
                'escalated': escalation_result['escalated'] if escalation_result else False,
            }
        }
    
    def _classify_error(self, error: Exception) -> str:
        """Classify error type for appropriate handling"""
        error_class_map = {
            # Database errors
            OperationalError: 'database_operational',
            DatabaseError: 'database_general',
            IntegrityError: 'database_integrity',
            
            # Validation errors
            ValidationError: 'validation',
            
            # System errors
            MemoryError: 'system_memory',
            TimeoutError: 'system_timeout',
            ConnectionError: 'system_connection',
            
            # File/IO errors
            FileNotFoundError: 'file_not_found',
            PermissionError: 'permission_denied',
            IOError: 'io_error',
            
            # Network errors
            OSError: 'network_error',
        }
        
        for error_class, error_type in error_class_map.items():
            if isinstance(error, error_class):
                return error_type
        
        # Check for custom business errors
        if hasattr(error, 'error_code'):
            return f"business_{error.error_code.lower()}"
        
        return 'unknown_error'
    
    def _determine_severity(self, error: Exception, error_cluster = None) -> ErrorSeverity:
        """Determine error severity based on type and frequency"""
        
        # Critical errors that always require immediate attention
        critical_errors = [MemoryError, SystemExit]
        if type(error) in critical_errors:
            return ErrorSeverity.CRITICAL
        
        # High severity based on error patterns
        high_severity_patterns = [
            'database.*connection',
            'out of memory',
            'disk.*full',
            'authentication.*failed'
        ]
        
        error_str = str(error).lower()
        if any(pattern in error_str for pattern in high_severity_patterns):
            return ErrorSeverity.HIGH
        
        # Check frequency from error cluster
        if error_cluster:
            if error_cluster.occurrence_count >= 20:
                return ErrorSeverity.HIGH
            elif error_cluster.occurrence_count >= 5:
                return ErrorSeverity.MEDIUM
        
        # Default severity by error type
        severity_map = {
            'database_operational': ErrorSeverity.HIGH,
            'system_memory': ErrorSeverity.CRITICAL,
            'system_timeout': ErrorSeverity.MEDIUM,
            'validation': ErrorSeverity.LOW,
            'permission_denied': ErrorSeverity.MEDIUM,
        }
        
        error_type = self._classify_error(error)
        return severity_map.get(error_type, ErrorSeverity.LOW)
    
    def _attempt_recovery(self, error: Exception, error_type: str, 
                         context: Dict[str, Any]) -> Optional[RecoveryResult]:
        """Attempt to recover from the error using appropriate strategy"""
        
        strategy = self._get_recovery_strategy(error_type, context)
        if not strategy:
            return None
        
        start_time = time.time()
        
        try:
            if strategy == RecoveryStrategy.IMMEDIATE_RETRY:
                result = self._immediate_retry_recovery(error, context)
            elif strategy == RecoveryStrategy.EXPONENTIAL_BACKOFF:
                result = self._exponential_backoff_recovery(error, context)
            elif strategy == RecoveryStrategy.FALLBACK_SERVICE:
                result = self._fallback_service_recovery(error, context)
            elif strategy == RecoveryStrategy.GRACEFUL_DEGRADATION:
                result = self._graceful_degradation_recovery(error, context)
            else:
                return None
            
            duration = (time.time() - start_time) * 1000
            
            return RecoveryResult(
                success=result['success'],
                strategy_used=strategy,
                attempts=result.get('attempts', 1),
                duration_ms=duration,
                fallback_used=result.get('fallback_used', False),
                user_message=result.get('user_message'),
                admin_message=result.get('admin_message'),
                next_action=result.get('next_action')
            )
            
        except Exception as recovery_error:
            self.logger.error(
                EventType.SYSTEM_ERROR,
                f"Recovery attempt failed for {error_type}",
                exception=recovery_error,
                extra_data={'original_error': str(error), 'strategy': strategy.value},
                tags=['recovery', 'failed']
            )
            return None
    
    def _get_recovery_strategy(self, error_type: str, context: Dict[str, Any]) -> Optional[RecoveryStrategy]:
        """Get appropriate recovery strategy for error type"""
        
        strategy_map = {
            'database_operational': RecoveryStrategy.EXPONENTIAL_BACKOFF,
            'database_general': RecoveryStrategy.FALLBACK_SERVICE,
            'system_timeout': RecoveryStrategy.IMMEDIATE_RETRY,
            'system_connection': RecoveryStrategy.EXPONENTIAL_BACKOFF,
            'validation': RecoveryStrategy.USER_INTERVENTION,
            'file_not_found': RecoveryStrategy.GRACEFUL_DEGRADATION,
            'permission_denied': RecoveryStrategy.ESCALATE_TO_ADMIN,
        }
        
        return strategy_map.get(error_type)
    
    def _immediate_retry_recovery(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """Immediate retry recovery strategy"""
        max_retries = context.get('max_retries', 3)
        operation = context.get('operation')
        
        for attempt in range(max_retries):
            try:
                time.sleep(0.1 * (attempt + 1))  # Brief delay
                
                if operation and callable(operation):
                    operation()
                    return {
                        'success': True,
                        'attempts': attempt + 1,
                        'user_message': 'The operation was completed successfully after a brief retry.'
                    }
                
            except Exception as retry_error:
                if attempt == max_retries - 1:
                    return {
                        'success': False,
                        'attempts': max_retries,
                        'user_message': 'The operation could not be completed after multiple attempts.',
                        'next_action': 'try_again_later'
                    }
                continue
        
        return {'success': False, 'attempts': max_retries}
    
    def _exponential_backoff_recovery(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """Exponential backoff recovery strategy"""
        max_retries = context.get('max_retries', 5)
        base_delay = context.get('base_delay', 1.0)
        operation = context.get('operation')
        
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    delay = base_delay * (2 ** (attempt - 1))
                    time.sleep(min(delay, 30))  # Max 30 seconds
                
                if operation and callable(operation):
                    operation()
                    return {
                        'success': True,
                        'attempts': attempt + 1,
                        'user_message': f'The operation completed successfully after {attempt + 1} attempts.'
                    }
                
            except Exception as retry_error:
                if attempt == max_retries - 1:
                    return {
                        'success': False,
                        'attempts': max_retries,
                        'user_message': 'The service is temporarily unavailable. Please try again in a few minutes.',
                        'next_action': 'try_again_later'
                    }
                continue
        
        return {'success': False, 'attempts': max_retries}
    
    def _fallback_service_recovery(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback service recovery strategy"""
        fallback_operation = context.get('fallback_operation')
        
        if fallback_operation and callable(fallback_operation):
            try:
                result = fallback_operation()
                return {
                    'success': True,
                    'attempts': 1,
                    'fallback_used': True,
                    'user_message': 'Your request was completed using an alternative method.',
                    'admin_message': f'Fallback service used for: {str(error)}'
                }
            except Exception as fallback_error:
                return {
                    'success': False,
                    'attempts': 1,
                    'fallback_used': True,
                    'user_message': 'Both primary and backup services are currently unavailable.',
                    'next_action': 'contact_support'
                }
        
        return {
            'success': False,
            'attempts': 0,
            'user_message': 'Service temporarily unavailable. Our team has been notified.',
            'next_action': 'contact_support'
        }
    
    def _graceful_degradation_recovery(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """Graceful degradation recovery strategy"""
        degraded_operation = context.get('degraded_operation')
        feature_name = context.get('feature_name', 'feature')
        
        if degraded_operation and callable(degraded_operation):
            try:
                result = degraded_operation()
                return {
                    'success': True,
                    'attempts': 1,
                    'fallback_used': True,
                    'user_message': f'The {feature_name} is running in limited mode. Some features may be unavailable.',
                    'admin_message': f'Graceful degradation activated for: {str(error)}'
                }
            except Exception as degraded_error:
                pass
        
        return {
            'success': True,
            'attempts': 1,
            'fallback_used': True,
            'user_message': f'The {feature_name} is temporarily limited. Core functionality remains available.',
            'next_action': 'continue_with_limitations'
        }
    
    def _create_user_friendly_error(self, error: Exception, error_type: str, 
                                   severity: ErrorSeverity, recovery_result: Optional[RecoveryResult]) -> UserFriendlyError:
        """Create user-friendly error representation"""
        
        # If recovery was successful, show success message
        if recovery_result and recovery_result.success:
            return UserFriendlyError(
                title="Request Completed",
                message=recovery_result.user_message or "Your request was completed successfully.",
                suggestions=[],
                severity=ErrorSeverity.LOW,
                retry_allowed=False
            )
        
        # Error-specific user-friendly messages
        error_messages = {
            'database_operational': UserFriendlyError(
                title="Service Temporarily Unavailable",
                message="We're experiencing temporary technical difficulties. Your data is safe.",
                suggestions=[
                    "Please try again in a few minutes",
                    "If the problem persists, contact our support team"
                ],
                help_url="/help/technical-issues",
                contact_support=True,
                retry_allowed=True,
                severity=severity
            ),
            
            'validation': UserFriendlyError(
                title="Invalid Information",
                message="Please check your input and try again.",
                suggestions=[
                    "Verify all required fields are filled",
                    "Check that email addresses and phone numbers are in the correct format",
                    "Ensure passwords meet the requirements"
                ],
                help_url="/help/data-validation",
                retry_allowed=True,
                severity=severity
            ),
            
            'permission_denied': UserFriendlyError(
                title="Access Denied",
                message="You don't have permission to perform this action.",
                suggestions=[
                    "Check that you're logged in with the correct account",
                    "Contact your administrator for access",
                    "Verify your account status"
                ],
                help_url="/help/permissions",
                contact_support=True,
                retry_allowed=False,
                severity=severity
            ),
            
            'system_timeout': UserFriendlyError(
                title="Request Timeout",
                message="Your request took too long to process.",
                suggestions=[
                    "Try again with a smaller amount of data",
                    "Check your internet connection",
                    "Try again in a few minutes"
                ],
                help_url="/help/timeouts",
                retry_allowed=True,
                severity=severity
            ),
            
            'file_not_found': UserFriendlyError(
                title="File Not Found",
                message="The requested file could not be found.",
                suggestions=[
                    "Check that the file name is correct",
                    "Verify the file hasn't been moved or deleted",
                    "Try uploading the file again"
                ],
                help_url="/help/file-management",
                retry_allowed=True,
                severity=severity
            ),
        }
        
        user_error = error_messages.get(error_type)
        
        if not user_error:
            # Generic user-friendly error
            user_error = UserFriendlyError(
                title="Something Went Wrong",
                message="We encountered an unexpected issue while processing your request.",
                suggestions=[
                    "Please try again",
                    "If the problem continues, contact our support team",
                    "Include any error details when contacting support"
                ],
                help_url="/help/general",
                contact_support=severity.requires_escalation,
                retry_allowed=True,
                severity=severity
            )
        
        return user_error
    
    def _check_escalation(self, error: Exception, severity: ErrorSeverity, 
                         error_cluster=None, recovery_result: Optional[RecoveryResult] = None) -> Dict[str, Any]:
        """Check if error requires escalation"""
        
        should_escalate = False
        escalation_reason = []
        escalation_level = 'none'
        
        # Automatic escalation based on severity
        if severity.requires_escalation:
            should_escalate = True
            escalation_reason.append(f"High severity error: {severity.level}")
            escalation_level = 'high_priority'
        
        # Escalation based on frequency
        if error_cluster and error_cluster.occurrence_count >= 10:
            should_escalate = True
            escalation_reason.append(f"High frequency error: {error_cluster.occurrence_count} occurrences")
            escalation_level = 'pattern_analysis'
        
        # Escalation based on recovery failure
        if recovery_result and not recovery_result.success:
            if recovery_result.attempts >= 5:
                should_escalate = True
                escalation_reason.append("Recovery attempts failed after multiple tries")
                escalation_level = 'recovery_failure'
        
        # Escalation based on user impact
        if error_cluster and len(error_cluster.unique_users) >= 5:
            should_escalate = True
            escalation_reason.append(f"Multiple users affected: {len(error_cluster.unique_users)}")
            escalation_level = 'user_impact'
        
        escalation_result = {
            'escalated': should_escalate,
            'level': escalation_level,
            'reasons': escalation_reason,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if should_escalate:
            self._escalate_error(error, severity, escalation_result, error_cluster)
        
        return escalation_result
    
    def _escalate_error(self, error: Exception, severity: ErrorSeverity, 
                       escalation_result: Dict[str, Any], error_cluster=None):
        """Escalate error to appropriate team/system"""
        
        escalation_data = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'severity': severity.level,
            'escalation_level': escalation_result['level'],
            'escalation_reasons': escalation_result['reasons'],
            'timestamp': escalation_result['timestamp'],
        }
        
        if error_cluster:
            escalation_data.update({
                'signature_hash': error_cluster.signature.signature_hash,
                'occurrence_count': error_cluster.occurrence_count,
                'affected_users': len(error_cluster.unique_users),
                'first_occurrence': error_cluster.first_occurrence,
            })
        
        # Log escalation
        self.logger.critical(
            EventType.SYSTEM_ERROR,
            f"Error escalated: {type(error).__name__}",
            extra_data=escalation_data,
            tags=['escalation', severity.level, escalation_result['level']]
        )
        
        # Send notifications based on escalation level
        if escalation_result['level'] in ['high_priority', 'user_impact']:
            self._send_escalation_notification(escalation_data, urgent=True)
        else:
            self._send_escalation_notification(escalation_data, urgent=False)
    
    def _send_escalation_notification(self, escalation_data: Dict[str, Any], urgent: bool = False):
        """Send escalation notification to appropriate channels"""
        
        try:
            # Send to monitoring system
            if hasattr(settings, 'MONITORING_WEBHOOK_URL'):
                import requests
                
                payload = {
                    'alert_type': 'error_escalation',
                    'priority': 'urgent' if urgent else 'high',
                    'data': escalation_data,
                    'timestamp': escalation_data['timestamp']
                }
                
                requests.post(
                    settings.MONITORING_WEBHOOK_URL,
                    json=payload,
                    timeout=10
                )
            
            # Send to Slack/Teams if configured
            if hasattr(settings, 'ESCALATION_SLACK_WEBHOOK'):
                self._send_slack_escalation(escalation_data, urgent)
                
        except Exception as notification_error:
            self.logger.error(
                EventType.SYSTEM_ERROR,
                "Failed to send escalation notification",
                exception=notification_error,
                extra_data=escalation_data,
                tags=['escalation', 'notification', 'failed']
            )
    
    def _send_slack_escalation(self, escalation_data: Dict[str, Any], urgent: bool):
        """Send escalation to Slack"""
        import requests
        
        color = "#ff0000" if urgent else "#ff9900"
        emoji = "🚨" if urgent else "⚠️"
        
        message = {
            "text": f"{emoji} Error Escalation - {escalation_data['severity'].upper()}",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": "Error Type", "value": escalation_data['error_type'], "short": True},
                        {"title": "Severity", "value": escalation_data['severity'].upper(), "short": True},
                        {"title": "Escalation Level", "value": escalation_data['escalation_level'], "short": True},
                        {"title": "Reasons", "value": "\n".join(escalation_data['escalation_reasons']), "short": False},
                    ],
                    "footer": "PRS Error Handling System",
                    "ts": int(datetime.utcnow().timestamp())
                }
            ]
        }
        
        requests.post(settings.ESCALATION_SLACK_WEBHOOK, json=message, timeout=10)
    
    def _log_error_handling(self, error: Exception, error_type: str, severity: ErrorSeverity,
                           recovery_result: Optional[RecoveryResult], user_error: UserFriendlyError,
                           escalation_result: Dict[str, Any], processing_time: float,
                           context: Dict[str, Any]):
        """Log comprehensive error handling information"""
        
        log_data = {
            'error_type': error_type,
            'error_class': type(error).__name__,
            'error_message': str(error),
            'severity': severity.level,
            'processing_time_ms': processing_time,
            'user_friendly_title': user_error.title,
            'recovery_attempted': recovery_result is not None,
            'recovery_successful': recovery_result.success if recovery_result else False,
            'escalated': escalation_result['escalated'],
            'context': context
        }
        
        if recovery_result:
            log_data['recovery_details'] = {
                'strategy': recovery_result.strategy_used.value,
                'attempts': recovery_result.attempts,
                'duration_ms': recovery_result.duration_ms,
                'fallback_used': recovery_result.fallback_used
            }
        
        self.logger.info(
            EventType.SYSTEM_ERROR,
            f"Error handled: {error_type} ({severity.level})",
            extra_data=log_data,
            tags=['error_handling', error_type, severity.level]
        )
    
    def _initialize_recovery_strategies(self) -> Dict[str, RecoveryStrategy]:
        """Initialize recovery strategies mapping"""
        return {
            'database_timeout': RecoveryStrategy.EXPONENTIAL_BACKOFF,
            'network_error': RecoveryStrategy.IMMEDIATE_RETRY,
            'service_unavailable': RecoveryStrategy.FALLBACK_SERVICE,
            'resource_exhausted': RecoveryStrategy.GRACEFUL_DEGRADATION,
        }
    
    def _initialize_error_mappings(self) -> Dict[Type[Exception], str]:
        """Initialize error type mappings"""
        return {
            DatabaseError: 'database_error',
            ValidationError: 'validation_error',
            PermissionError: 'permission_error',
            TimeoutError: 'timeout_error',
        }
    
    def _initialize_escalation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize escalation rules"""
        return {
            'frequency_threshold': {'count': 10, 'time_window': 3600},
            'severity_escalation': {
                'critical': {'immediate': True, 'channels': ['slack', 'pager']},
                'high': {'delay': 300, 'channels': ['slack', 'email']},
                'medium': {'delay': 1800, 'channels': ['email']},
            }
        }


# Global error handler instance
enhanced_error_handler = EnhancedErrorHandler()


# Context manager for error handling
@contextmanager
def error_handling_context(operation_name: str, user_id: int = None, 
                          max_retries: int = 3, fallback_operation: Callable = None,
                          degraded_operation: Callable = None):
    """
    Context manager for enhanced error handling
    
    Usage:
        with error_handling_context('user_login', user_id=123) as ctx:
            # Risky operation
            perform_user_login()
    """
    import uuid
    
    request_id = str(uuid.uuid4())
    context = {
        'operation_name': operation_name,
        'max_retries': max_retries,
        'fallback_operation': fallback_operation,
        'degraded_operation': degraded_operation,
        'start_time': time.time()
    }
    
    try:
        yield context
        
        # Log successful operation
        duration = (time.time() - context['start_time']) * 1000
        log_business_event(
            f"{operation_name}_completed",
            user_id=user_id,
            duration_ms=duration
        )
        
    except Exception as error:
        # Handle error with enhanced error handler
        error_response = enhanced_error_handler.handle_error(
            error=error,
            context=context,
            user_id=user_id,
            request_id=request_id
        )
        
        # Re-raise with enhanced error information
        enhanced_error = EnhancedAPIException(
            detail=error_response['error'],
            code=error_response['error']['type'],
            recovery_info=error_response['recovery'],
            meta=error_response['meta']
        )
        
        raise enhanced_error


class EnhancedAPIException(APIException):
    """
    Enhanced API exception with recovery information and user-friendly messages
    """
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'An unexpected error occurred.'
    default_code = 'internal_error'
    
    def __init__(self, detail=None, code=None, recovery_info=None, meta=None):
        super().__init__(detail, code)
        self.recovery_info = recovery_info or {}
        self.meta = meta or {}
    
    def get_full_details(self):
        """Get full error details including recovery information"""
        return {
            'error': self.detail,
            'recovery': self.recovery_info,
            'meta': self.meta
        }


# Convenience functions
def handle_database_error(error: DatabaseError, operation: str = None, 
                         user_id: int = None) -> Dict[str, Any]:
    """Handle database errors with recovery"""
    return enhanced_error_handler.handle_error(
        error=error,
        context={'operation_name': operation, 'error_category': 'database'},
        user_id=user_id
    )


def handle_validation_error(error: ValidationError, form_data: Dict = None,
                           user_id: int = None) -> Dict[str, Any]:
    """Handle validation errors with user guidance"""
    return enhanced_error_handler.handle_error(
        error=error,
        context={'operation_name': 'validation', 'form_data': form_data},
        user_id=user_id
    )


def handle_permission_error(error: PermissionError, resource: str = None,
                           user_id: int = None) -> Dict[str, Any]:
    """Handle permission errors with escalation"""
    return enhanced_error_handler.handle_error(
        error=error,
        context={'operation_name': 'permission_check', 'resource': resource},
        user_id=user_id
    )
