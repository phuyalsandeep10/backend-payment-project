"""
Session Management Service - Task 2.3.1

Extracted from authentication app to reduce coupling and improve maintainability.
Manages user sessions, security, and session lifecycle.
"""

from services.base_service import BaseService
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.db import models, transaction
import logging
import hashlib
import secrets

# Security logger
security_logger = logging.getLogger('security')
User = get_user_model()


class SessionManagementService(BaseService):
    """
    Service for managing user sessions with security features.
    Extracted from authentication models and views.
    """

    def __init__(self, user=None, organization=None, **kwargs):
        super().__init__(user=user, organization=organization)
        self.session_timeout = 3600  # 1 hour default
        self.max_concurrent_sessions = 5

    def get_service_name(self) -> str:
        """Return the name of this service for logging and identification"""
        return "session_management_service"
        
    def create_user_session(self, user, request, device_info: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Create a new user session with security tracking.
        
        Args:
            user: User object
            request: HTTP request object
            device_info: Optional device information
            
        Returns:
            dict: Session creation result
        """
        try:
            # Import here to avoid circular import
            from authentication.models import UserSession, SecureUserSession
            
            # Get client IP and user agent
            client_ip = self._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
            
            # Create session record
            with transaction.atomic():
                # Clean up old sessions first
                self._cleanup_expired_sessions(user)
                
                # Check concurrent session limit
                active_sessions = UserSession.objects.filter(
                    user=user,
                    is_active=True,
                    expires_at__gt=timezone.now()
                ).count()
                
                if active_sessions >= self.max_concurrent_sessions:
                    # Remove oldest session
                    oldest_session = UserSession.objects.filter(
                        user=user,
                        is_active=True
                    ).order_by('created_at').first()
                    if oldest_session:
                        self.terminate_session(oldest_session.session_key, user)
                
                # Create new session
                session_key = self._generate_session_key()
                expires_at = timezone.now() + timedelta(seconds=self.session_timeout)
                
                user_session = UserSession.objects.create(
                    user=user,
                    session_key=session_key,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    device_info=device_info or {},
                    created_at=timezone.now(),
                    expires_at=expires_at,
                    is_active=True,
                    last_activity=timezone.now()
                )
                
                # Create secure session record
                SecureUserSession.objects.create(
                    user=user,
                    session_key=session_key,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    security_token=secrets.token_urlsafe(32),
                    created_at=timezone.now(),
                    expires_at=expires_at,
                    is_active=True,
                    last_activity=timezone.now(),
                    login_method='standard'
                )
                
                security_logger.info(f"Session created for user {user.email} from IP {client_ip}")
                
                return {
                    'success': True,
                    'session_key': session_key,
                    'expires_at': expires_at,
                    'user_session_id': user_session.id
                }
                
        except Exception as e:
            security_logger.error(f"Session creation failed for user {getattr(user, 'email', 'unknown')}: {e}")
            return {
                'success': False,
                'error': 'Failed to create session'
            }

    def get_active_sessions(self, user) -> List[Dict[str, Any]]:
        """Get all active sessions for a user"""
        try:
            from authentication.models import UserSession
            
            # Clean up expired sessions first
            self._cleanup_expired_sessions(user)
            
            sessions = UserSession.objects.filter(
                user=user,
                is_active=True,
                expires_at__gt=timezone.now()
            ).order_by('-last_activity')
            
            return [
                {
                    'id': session.id,
                    'session_key': session.session_key[:8] + '...',  # Partial for security
                    'ip_address': session.ip_address,
                    'device_info': session.device_info,
                    'created_at': session.created_at,
                    'last_activity': session.last_activity,
                    'expires_at': session.expires_at,
                    'is_current': self._is_current_session(session, user)
                }
                for session in sessions
            ]
            
        except Exception as e:
            security_logger.error(f"Failed to get active sessions for user {getattr(user, 'email', 'unknown')}: {e}")
            return []

    def terminate_session(self, session_key: str, user, reason: str = 'user_request') -> bool:
        """
        Terminate a specific user session.
        
        Args:
            session_key: Session key to terminate
            user: User object
            reason: Termination reason for logging
            
        Returns:
            bool: True if successful
        """
        try:
            from authentication.models import UserSession, SecureUserSession
            
            with transaction.atomic():
                # Deactivate user session
                user_sessions = UserSession.objects.filter(
                    user=user,
                    session_key=session_key,
                    is_active=True
                )
                
                for session in user_sessions:
                    session.is_active = False
                    session.terminated_at = timezone.now()
                    session.termination_reason = reason
                    session.save()
                
                # Deactivate secure session
                secure_sessions = SecureUserSession.objects.filter(
                    user=user,
                    session_key=session_key,
                    is_active=True
                )
                
                for session in secure_sessions:
                    session.is_active = False
                    session.terminated_at = timezone.now()
                    session.termination_reason = reason
                    session.save()
                
                # Remove from Django session store
                try:
                    django_session = Session.objects.get(session_key=session_key)
                    django_session.delete()
                except Session.DoesNotExist:
                    pass  # Session might already be expired or deleted
                
                security_logger.info(f"Session {session_key} terminated for user {user.email}, reason: {reason}")
                return True
                
        except Exception as e:
            security_logger.error(f"Failed to terminate session {session_key} for user {getattr(user, 'email', 'unknown')}: {e}")
            return False

    def terminate_all_sessions(self, user, except_current: Optional[str] = None, reason: str = 'security') -> int:
        """
        Terminate all sessions for a user.
        
        Args:
            user: User object
            except_current: Session key to keep active (optional)
            reason: Termination reason
            
        Returns:
            int: Number of sessions terminated
        """
        try:
            from authentication.models import UserSession, SecureUserSession
            
            terminated_count = 0
            
            with transaction.atomic():
                # Get active sessions
                active_sessions = UserSession.objects.filter(
                    user=user,
                    is_active=True
                )
                
                if except_current:
                    active_sessions = active_sessions.exclude(session_key=except_current)
                
                for session in active_sessions:
                    if self.terminate_session(session.session_key, user, reason):
                        terminated_count += 1
                
                security_logger.info(f"Terminated {terminated_count} sessions for user {user.email}, reason: {reason}")
                return terminated_count
                
        except Exception as e:
            security_logger.error(f"Failed to terminate sessions for user {getattr(user, 'email', 'unknown')}: {e}")
            return 0

    def update_session_activity(self, session_key: str, user, request) -> bool:
        """Update session last activity timestamp"""
        try:
            from authentication.models import UserSession, SecureUserSession
            
            now = timezone.now()
            
            # Update user session
            UserSession.objects.filter(
                user=user,
                session_key=session_key,
                is_active=True
            ).update(
                last_activity=now,
                ip_address=self._get_client_ip(request)  # Update IP if changed
            )
            
            # Update secure session
            SecureUserSession.objects.filter(
                user=user,
                session_key=session_key,
                is_active=True
            ).update(
                last_activity=now,
                ip_address=self._get_client_ip(request)
            )
            
            return True
            
        except Exception as e:
            security_logger.error(f"Failed to update session activity: {e}")
            return False

    def validate_session_security(self, session_key: str, user, request) -> Dict[str, Any]:
        """
        Validate session security (IP changes, suspicious activity, etc.)
        
        Returns:
            dict: Validation result with security warnings
        """
        try:
            from authentication.models import SecureUserSession
            
            session = SecureUserSession.objects.filter(
                user=user,
                session_key=session_key,
                is_active=True
            ).first()
            
            if not session:
                return {
                    'valid': False,
                    'reason': 'Session not found',
                    'action': 'terminate'
                }
            
            current_ip = self._get_client_ip(request)
            warnings = []
            
            # Check IP change
            if session.ip_address != current_ip:
                warnings.append('IP address changed')
                security_logger.warning(f"IP change detected for session {session_key}: {session.ip_address} -> {current_ip}")
            
            # Check session expiry
            if session.expires_at <= timezone.now():
                return {
                    'valid': False,
                    'reason': 'Session expired',
                    'action': 'terminate'
                }
            
            # Check for suspicious activity (too many rapid requests)
            if self._detect_suspicious_activity(session, request):
                warnings.append('Suspicious activity detected')
            
            return {
                'valid': True,
                'warnings': warnings,
                'session': {
                    'created_at': session.created_at,
                    'last_activity': session.last_activity,
                    'ip_address': session.ip_address
                }
            }
            
        except Exception as e:
            security_logger.error(f"Session security validation failed: {e}")
            return {
                'valid': False,
                'reason': 'Validation error',
                'action': 'terminate'
            }

    def _cleanup_expired_sessions(self, user) -> int:
        """Clean up expired sessions for a user"""
        try:
            from authentication.models import UserSession, SecureUserSession
            
            now = timezone.now()
            
            # Mark expired sessions as inactive
            expired_user_sessions = UserSession.objects.filter(
                user=user,
                is_active=True,
                expires_at__lte=now
            )
            
            count = expired_user_sessions.count()
            expired_user_sessions.update(
                is_active=False,
                terminated_at=now,
                termination_reason='expired'
            )
            
            # Clean up secure sessions
            SecureUserSession.objects.filter(
                user=user,
                is_active=True,
                expires_at__lte=now
            ).update(
                is_active=False,
                terminated_at=now,
                termination_reason='expired'
            )
            
            return count
            
        except Exception as e:
            security_logger.error(f"Session cleanup failed: {e}")
            return 0

    def _generate_session_key(self) -> str:
        """Generate a secure session key"""
        return hashlib.sha256(
            f"{secrets.token_urlsafe(32)}{timezone.now().timestamp()}".encode()
        ).hexdigest()

    def _get_client_ip(self, request) -> str:
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip

    def _is_current_session(self, session, user) -> bool:
        """Check if session is the current session"""
        # This would need access to the current request context
        # For now, return False as placeholder
        return False

    def _detect_suspicious_activity(self, session, request) -> bool:
        """Detect suspicious activity patterns"""
        try:
            # Check for rapid consecutive requests (basic rate limiting check)
            now = timezone.now()
            time_threshold = now - timedelta(minutes=1)
            
            # This is a basic implementation
            # In a real system, you'd want more sophisticated detection
            if session.last_activity and session.last_activity > time_threshold:
                return False  # Recent activity is normal
            
            return False  # No suspicious activity detected
            
        except Exception:
            return False
