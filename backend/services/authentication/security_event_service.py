"""
Security Event Service - Task 2.3.1

Extracted from authentication app and core_config to reduce coupling.
Centralized security event logging and monitoring for authentication events.
"""

from services.base_service import BaseService
from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.cache import cache
import logging
import json

# Security logger
security_logger = logging.getLogger('security')
User = get_user_model()


class SecurityEventService(BaseService):
    """
    Service for logging and managing security events.
    Extracted from core_config.error_handling.security_event_logger
    """

    # Event type constants
    EVENT_TYPES = {
        'LOGIN_SUCCESS': 'login_success',
        'LOGIN_FAILED': 'login_failed',
        'LOGIN_BLOCKED': 'login_blocked',
        'LOGOUT': 'logout',
        'PASSWORD_CHANGE': 'password_change',
        'PASSWORD_RESET': 'password_reset',
        'ACCOUNT_LOCKED': 'account_locked',
        'ACCOUNT_UNLOCKED': 'account_unlocked',
        'PERMISSION_DENIED': 'permission_denied',
        'SUSPICIOUS_ACTIVITY': 'suspicious_activity',
        'SESSION_HIJACK': 'session_hijack',
        'MULTIPLE_FAILED_ATTEMPTS': 'multiple_failed_attempts',
        'IP_ADDRESS_CHANGE': 'ip_address_change',
        'ADMIN_ACCESS': 'admin_access'
    }

    # Risk levels
    RISK_LEVELS = {
        'LOW': 1,
        'MEDIUM': 2,
        'HIGH': 3,
        'CRITICAL': 4
    }

    def __init__(self, user=None, organization=None, **kwargs):
        super().__init__(user=user, organization=organization)
        self.max_failed_attempts = 5
        self.lockout_duration = 1800  # 30 minutes

    def get_service_name(self) -> str:
        """Return the name of this service for logging and identification"""
        return "security_event_service"

    def log_authentication_attempt(self, request, email: str, success: bool, 
                                 failure_reason: Optional[str] = None, 
                                 additional_data: Optional[Dict] = None) -> bool:
        """
        Log authentication attempt with security context.
        
        Args:
            request: HTTP request object
            email: User email attempting authentication
            success: Whether authentication was successful
            failure_reason: Reason for failure (if applicable)
            additional_data: Additional context data
            
        Returns:
            bool: True if logged successfully
        """
        try:
            event_type = self.EVENT_TYPES['LOGIN_SUCCESS'] if success else self.EVENT_TYPES['LOGIN_FAILED']
            risk_level = self.RISK_LEVELS['LOW'] if success else self.RISK_LEVELS['MEDIUM']
            
            # Get user if exists
            user = None
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                pass
            
            # Enhanced failure tracking
            if not success:
                failed_attempts = self._track_failed_attempts(email, request)
                if failed_attempts >= self.max_failed_attempts:
                    risk_level = self.RISK_LEVELS['HIGH']
                    event_type = self.EVENT_TYPES['LOGIN_BLOCKED']
                    self._lock_account_temporarily(email)
            
            event_data = {
                'event_type': event_type,
                'email': email,
                'user_id': user.id if user else None,
                'ip_address': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
                'timestamp': timezone.now().isoformat(),
                'success': success,
                'failure_reason': failure_reason,
                'risk_level': risk_level,
                'session_key': getattr(request, 'session', {}).get('session_key', ''),
                'additional_data': additional_data or {}
            }
            
            # Log to security logger
            log_message = f"Auth attempt: {email} from {event_data['ip_address']} - {'SUCCESS' if success else 'FAILED'}"
            if failure_reason:
                log_message += f" ({failure_reason})"
                
            if success:
                security_logger.info(log_message, extra=event_data)
            else:
                security_logger.warning(log_message, extra=event_data)
            
            # Store in database for analysis
            self._store_security_event(event_data)
            
            return True
            
        except Exception as e:
            security_logger.error(f"Failed to log authentication attempt: {e}")
            return False

    def log_password_change(self, user, request, success: bool, method: str = 'user_initiated') -> bool:
        """Log password change events"""
        try:
            event_data = {
                'event_type': self.EVENT_TYPES['PASSWORD_CHANGE'],
                'user_id': user.id,
                'email': user.email,
                'ip_address': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
                'timestamp': timezone.now().isoformat(),
                'success': success,
                'method': method,
                'risk_level': self.RISK_LEVELS['MEDIUM']
            }
            
            log_message = f"Password change: {user.email} - {'SUCCESS' if success else 'FAILED'} ({method})"
            security_logger.info(log_message, extra=event_data)
            
            self._store_security_event(event_data)
            return True
            
        except Exception as e:
            security_logger.error(f"Failed to log password change: {e}")
            return False

    def log_permission_denied(self, user, request, resource: str, action: str) -> bool:
        """Log permission denied events"""
        try:
            event_data = {
                'event_type': self.EVENT_TYPES['PERMISSION_DENIED'],
                'user_id': user.id if user else None,
                'email': user.email if user else 'anonymous',
                'ip_address': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
                'timestamp': timezone.now().isoformat(),
                'resource': resource,
                'action': action,
                'risk_level': self.RISK_LEVELS['MEDIUM']
            }
            
            log_message = f"Permission denied: {event_data['email']} tried {action} on {resource}"
            security_logger.warning(log_message, extra=event_data)
            
            self._store_security_event(event_data)
            return True
            
        except Exception as e:
            security_logger.error(f"Failed to log permission denied: {e}")
            return False

    def log_suspicious_activity(self, user, request, activity_type: str, details: Dict) -> bool:
        """Log suspicious activity"""
        try:
            event_data = {
                'event_type': self.EVENT_TYPES['SUSPICIOUS_ACTIVITY'],
                'user_id': user.id if user else None,
                'email': user.email if user else 'unknown',
                'ip_address': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
                'timestamp': timezone.now().isoformat(),
                'activity_type': activity_type,
                'details': details,
                'risk_level': self.RISK_LEVELS['HIGH']
            }
            
            log_message = f"Suspicious activity: {activity_type} by {event_data['email']}"
            security_logger.warning(log_message, extra=event_data)
            
            self._store_security_event(event_data)
            
            # Trigger additional security measures if needed
            self._handle_suspicious_activity(event_data)
            
            return True
            
        except Exception as e:
            security_logger.error(f"Failed to log suspicious activity: {e}")
            return False

    def log_session_event(self, user, request, event_type: str, session_key: str, 
                         additional_data: Optional[Dict] = None) -> bool:
        """Log session-related security events"""
        try:
            event_data = {
                'event_type': event_type,
                'user_id': user.id,
                'email': user.email,
                'ip_address': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
                'timestamp': timezone.now().isoformat(),
                'session_key': session_key[:8] + '...',  # Partial session key for privacy
                'risk_level': self.RISK_LEVELS['MEDIUM'],
                'additional_data': additional_data or {}
            }
            
            log_message = f"Session event: {event_type} for {user.email}"
            security_logger.info(log_message, extra=event_data)
            
            self._store_security_event(event_data)
            return True
            
        except Exception as e:
            security_logger.error(f"Failed to log session event: {e}")
            return False

    def get_recent_security_events(self, user=None, hours: int = 24, event_types: List[str] = None) -> List[Dict]:
        """Get recent security events for analysis"""
        try:
            # This would typically query a security events database table
            # For now, we'll return cached events
            cache_key = f"security_events_{user.id if user else 'all'}_{hours}h"
            events = cache.get(cache_key, [])
            
            # Filter by event types if specified
            if event_types:
                events = [e for e in events if e.get('event_type') in event_types]
            
            return events
            
        except Exception as e:
            security_logger.error(f"Failed to get security events: {e}")
            return []

    def check_account_lockout(self, email: str) -> Dict[str, Any]:
        """Check if account is locked due to failed attempts"""
        try:
            cache_key = f"account_lockout_{email}"
            lockout_data = cache.get(cache_key)
            
            if not lockout_data:
                return {'locked': False}
            
            # Check if lockout has expired
            lockout_until = datetime.fromisoformat(lockout_data['locked_until'])
            if timezone.now() > lockout_until:
                cache.delete(cache_key)
                return {'locked': False}
            
            return {
                'locked': True,
                'locked_until': lockout_until,
                'reason': lockout_data.get('reason', 'Too many failed attempts'),
                'failed_attempts': lockout_data.get('failed_attempts', 0)
            }
            
        except Exception as e:
            security_logger.error(f"Failed to check account lockout: {e}")
            return {'locked': False, 'error': str(e)}

    def _track_failed_attempts(self, email: str, request) -> int:
        """Track failed login attempts"""
        try:
            cache_key = f"failed_attempts_{email}"
            ip_cache_key = f"failed_attempts_ip_{self._get_client_ip(request)}"
            
            # Track by email
            email_attempts = cache.get(cache_key, 0) + 1
            cache.set(cache_key, email_attempts, 3600)  # 1 hour
            
            # Track by IP
            ip_attempts = cache.get(ip_cache_key, 0) + 1
            cache.set(ip_cache_key, ip_attempts, 3600)
            
            return max(email_attempts, ip_attempts)
            
        except Exception as e:
            security_logger.error(f"Failed to track failed attempts: {e}")
            return 0

    def _lock_account_temporarily(self, email: str) -> bool:
        """Temporarily lock account due to excessive failed attempts"""
        try:
            lockout_until = timezone.now() + timedelta(seconds=self.lockout_duration)
            cache_key = f"account_lockout_{email}"
            
            lockout_data = {
                'locked_until': lockout_until.isoformat(),
                'reason': 'Too many failed login attempts',
                'failed_attempts': self.max_failed_attempts,
                'locked_at': timezone.now().isoformat()
            }
            
            cache.set(cache_key, lockout_data, self.lockout_duration)
            
            security_logger.warning(f"Account temporarily locked: {email} until {lockout_until}")
            return True
            
        except Exception as e:
            security_logger.error(f"Failed to lock account: {e}")
            return False

    def _store_security_event(self, event_data: Dict) -> bool:
        """Store security event in database for long-term analysis"""
        try:
            # In a real implementation, this would store in a SecurityEvent model
            # For now, we'll cache recent events for short-term analysis
            cache_key = f"recent_security_events"
            recent_events = cache.get(cache_key, [])
            
            # Add new event
            recent_events.append(event_data)
            
            # Keep only last 100 events
            recent_events = recent_events[-100:]
            
            # Cache for 24 hours
            cache.set(cache_key, recent_events, 86400)
            
            return True
            
        except Exception as e:
            security_logger.error(f"Failed to store security event: {e}")
            return False

    def _handle_suspicious_activity(self, event_data: Dict) -> None:
        """Handle suspicious activity by implementing additional security measures"""
        try:
            activity_type = event_data.get('activity_type', '')
            email = event_data.get('email', '')
            
            # Example responses to suspicious activity
            if 'multiple_locations' in activity_type:
                # Could trigger additional verification requirements
                security_logger.warning(f"Multiple location access detected for {email}")
            
            elif 'rapid_requests' in activity_type:
                # Could implement rate limiting
                security_logger.warning(f"Rapid requests detected for {email}")
            
            # Add more sophisticated responses as needed
            
        except Exception as e:
            security_logger.error(f"Failed to handle suspicious activity: {e}")

    def _get_client_ip(self, request) -> str:
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip
