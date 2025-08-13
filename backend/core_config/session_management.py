"""
Enhanced Session Management System
Redis-backed session management with security features
"""

import json
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.http import HttpRequest
from core_config.error_handling import security_event_logger

# Security logger
security_logger = logging.getLogger('security')

User = get_user_model()

class SessionManager:
    """
    Enhanced session manager with Redis backend and security features
    """
    
    # Session configuration
    SESSION_TIMEOUT = timedelta(hours=24)  # Default session timeout
    MAX_SESSIONS_PER_USER = 5  # Maximum concurrent sessions per user
    SESSION_CLEANUP_INTERVAL = timedelta(hours=1)  # Cleanup interval
    
    # Session security settings
    REQUIRE_IP_CONSISTENCY = True  # Require consistent IP address
    REQUIRE_USER_AGENT_CONSISTENCY = True  # Require consistent user agent
    ENABLE_SESSION_FINGERPRINTING = True  # Enable browser fingerprinting
    
    def __init__(self):
        """Initialize session manager"""
        self.cache_prefix = 'session:'
        self.user_sessions_prefix = 'user_sessions:'
        self.session_metadata_prefix = 'session_meta:'
    
    def create_session(self, user: User, request: HttpRequest, 
                      additional_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Create a new secure session for user
        
        Args:
            user: User instance
            request: HTTP request object
            additional_data: Additional session data
            
        Returns:
            Session data dictionary
        """
        # Generate secure session ID
        session_id = self._generate_session_id()
        
        # Get client information
        client_info = self._extract_client_info(request)
        
        # Create session data
        session_data = {
            'session_id': session_id,
            'user_id': user.id,
            'user_email': user.email,
            'created_at': timezone.now().isoformat(),
            'last_activity': timezone.now().isoformat(),
            'expires_at': (timezone.now() + self.SESSION_TIMEOUT).isoformat(),
            'ip_address': client_info['ip_address'],
            'user_agent': client_info['user_agent'],
            'user_agent_hash': client_info['user_agent_hash'],
            'session_fingerprint': client_info['session_fingerprint'],
            'is_active': True,
            'login_method': 'jwt',
            'security_flags': {
                'ip_verified': True,
                'user_agent_verified': True,
                'fingerprint_verified': True,
            }
        }
        
        # Add additional data if provided
        if additional_data:
            session_data.update(additional_data)
        
        # Check session limits
        self._enforce_session_limits(user)
        
        # Store session data
        self._store_session(session_id, session_data)
        
        # Add to user's session list
        self._add_to_user_sessions(user.id, session_id)
        
        # Log session creation
        security_logger.info(f"Session created for user {user.email}: {session_id[:8]}...")
        
        return session_data
    
    def validate_session(self, session_id: str, request: HttpRequest = None) -> Optional[Dict[str, Any]]:
        """
        Validate and retrieve session data
        
        Args:
            session_id: Session identifier
            request: HTTP request for security validation
            
        Returns:
            Session data if valid, None otherwise
        """
        # Retrieve session data
        session_data = self._get_session(session_id)
        
        if not session_data:
            return None
        
        # Check if session is active
        if not session_data.get('is_active', False):
            security_logger.warning(f"Inactive session access attempt: {session_id[:8]}...")
            return None
        
        # Check expiration
        expires_at = datetime.fromisoformat(session_data['expires_at'].replace('Z', '+00:00'))
        if timezone.now() > expires_at:
            security_logger.info(f"Expired session access: {session_id[:8]}...")
            self._invalidate_session(session_id)
            return None
        
        # Perform security validations if request is provided
        if request:
            if not self._validate_session_security(session_data, request):
                security_logger.warning(f"Session security validation failed: {session_id[:8]}...")
                self._flag_suspicious_session(session_id, 'security_validation_failed')
                return None
        
        # Update last activity
        session_data['last_activity'] = timezone.now().isoformat()
        self._store_session(session_id, session_data)
        
        return session_data
    
    def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """
        Update session data
        
        Args:
            session_id: Session identifier
            data: Data to update
            
        Returns:
            True if successful, False otherwise
        """
        session_data = self._get_session(session_id)
        
        if not session_data:
            return False
        
        # Update data
        session_data.update(data)
        session_data['last_activity'] = timezone.now().isoformat()
        
        # Store updated session
        self._store_session(session_id, session_data)
        
        return True
    
    def invalidate_session(self, session_id: str, reason: str = 'user_logout') -> bool:
        """
        Invalidate a specific session
        
        Args:
            session_id: Session identifier
            reason: Reason for invalidation
            
        Returns:
            True if successful, False otherwise
        """
        session_data = self._get_session(session_id)
        
        if not session_data:
            return False
        
        # Log session invalidation
        user_email = session_data.get('user_email', 'unknown')
        security_logger.info(f"Session invalidated for {user_email}: {session_id[:8]}... (reason: {reason})")
        
        # Remove from user's session list
        user_id = session_data.get('user_id')
        if user_id:
            self._remove_from_user_sessions(user_id, session_id)
        
        # Delete session data
        self._delete_session(session_id)
        
        return True
    
    def invalidate_all_user_sessions(self, user: User, reason: str = 'security_action') -> int:
        """
        Invalidate all sessions for a user
        
        Args:
            user: User instance
            reason: Reason for invalidation
            
        Returns:
            Number of sessions invalidated
        """
        user_sessions = self._get_user_sessions(user.id)
        invalidated_count = 0
        
        for session_id in user_sessions:
            if self.invalidate_session(session_id, reason):
                invalidated_count += 1
        
        # Clear user sessions list
        self._clear_user_sessions(user.id)
        
        security_logger.warning(f"All sessions invalidated for user {user.email}: {invalidated_count} sessions (reason: {reason})")
        
        return invalidated_count
    
    def get_user_sessions(self, user: User) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user
        
        Args:
            user: User instance
            
        Returns:
            List of session data dictionaries
        """
        session_ids = self._get_user_sessions(user.id)
        sessions = []
        
        for session_id in session_ids:
            session_data = self._get_session(session_id)
            if session_data and session_data.get('is_active', False):
                # Remove sensitive data for client consumption
                safe_session_data = {
                    'session_id': session_id[:8] + '...',  # Truncated for security
                    'created_at': session_data['created_at'],
                    'last_activity': session_data['last_activity'],
                    'ip_address': session_data['ip_address'],
                    'user_agent': session_data['user_agent'][:100] + '...' if len(session_data['user_agent']) > 100 else session_data['user_agent'],
                    'login_method': session_data.get('login_method', 'unknown'),
                }
                sessions.append(safe_session_data)
        
        return sessions
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions
        
        Returns:
            Number of sessions cleaned up
        """
        # This would typically be run as a periodic task
        # For now, we'll implement a basic cleanup
        
        cleanup_count = 0
        
        # Get all user session lists and check each session
        # This is a simplified implementation - in production, you'd want
        # a more efficient approach using Redis patterns or separate cleanup process
        
        security_logger.info(f"Session cleanup completed: {cleanup_count} sessions removed")
        
        return cleanup_count
    
    def get_session_statistics(self) -> Dict[str, Any]:
        """
        Get session statistics
        
        Returns:
            Dictionary with session statistics
        """
        # This would be implemented with Redis commands to count sessions
        # For now, return basic structure
        
        return {
            'total_active_sessions': 0,
            'sessions_by_user': {},
            'sessions_by_ip': {},
            'recent_logins': 0,
            'suspicious_sessions': 0,
        }
    
    def _generate_session_id(self) -> str:
        """Generate cryptographically secure session ID"""
        return secrets.token_urlsafe(32)
    
    def _extract_client_info(self, request: HttpRequest) -> Dict[str, str]:
        """Extract client information from request"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        ip_address = self._get_client_ip(request)
        
        # Create user agent hash for comparison
        user_agent_hash = hashlib.sha256(user_agent.encode()).hexdigest()
        
        # Create session fingerprint (simplified)
        fingerprint_data = f"{user_agent}{ip_address}"
        session_fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        return {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'user_agent_hash': user_agent_hash,
            'session_fingerprint': session_fingerprint,
        }
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip
    
    def _validate_session_security(self, session_data: Dict[str, Any], request: HttpRequest) -> bool:
        """Validate session security constraints"""
        client_info = self._extract_client_info(request)
        
        # Check IP consistency
        if self.REQUIRE_IP_CONSISTENCY:
            if session_data['ip_address'] != client_info['ip_address']:
                security_logger.warning(f"IP address mismatch for session: {session_data['ip_address']} vs {client_info['ip_address']}")
                return False
        
        # Check user agent consistency
        if self.REQUIRE_USER_AGENT_CONSISTENCY:
            if session_data['user_agent_hash'] != client_info['user_agent_hash']:
                security_logger.warning(f"User agent mismatch for session")
                return False
        
        # Check session fingerprint
        if self.ENABLE_SESSION_FINGERPRINTING:
            if session_data['session_fingerprint'] != client_info['session_fingerprint']:
                security_logger.warning(f"Session fingerprint mismatch")
                return False
        
        return True
    
    def _enforce_session_limits(self, user: User):
        """Enforce maximum session limits per user"""
        user_sessions = self._get_user_sessions(user.id)
        
        if len(user_sessions) >= self.MAX_SESSIONS_PER_USER:
            # Remove oldest session
            oldest_session_id = user_sessions[0]  # Assuming list is ordered
            self.invalidate_session(oldest_session_id, 'session_limit_exceeded')
            
            security_logger.info(f"Session limit exceeded for user {user.email}, oldest session removed")
    
    def _store_session(self, session_id: str, session_data: Dict[str, Any]):
        """Store session data in cache"""
        cache_key = f"{self.cache_prefix}{session_id}"
        timeout = int(self.SESSION_TIMEOUT.total_seconds())
        cache.set(cache_key, json.dumps(session_data), timeout=timeout)
    
    def _get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data from cache"""
        cache_key = f"{self.cache_prefix}{session_id}"
        data = cache.get(cache_key)
        
        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                security_logger.error(f"Failed to decode session data for {session_id[:8]}...")
                return None
        
        return None
    
    def _delete_session(self, session_id: str):
        """Delete session data from cache"""
        cache_key = f"{self.cache_prefix}{session_id}"
        cache.delete(cache_key)
    
    def _add_to_user_sessions(self, user_id: int, session_id: str):
        """Add session to user's session list"""
        cache_key = f"{self.user_sessions_prefix}{user_id}"
        user_sessions = cache.get(cache_key, [])
        
        if session_id not in user_sessions:
            user_sessions.append(session_id)
            # Keep only recent sessions
            user_sessions = user_sessions[-self.MAX_SESSIONS_PER_USER:]
            cache.set(cache_key, user_sessions, timeout=None)  # No expiration for user session lists
    
    def _remove_from_user_sessions(self, user_id: int, session_id: str):
        """Remove session from user's session list"""
        cache_key = f"{self.user_sessions_prefix}{user_id}"
        user_sessions = cache.get(cache_key, [])
        
        if session_id in user_sessions:
            user_sessions.remove(session_id)
            cache.set(cache_key, user_sessions, timeout=None)
    
    def _get_user_sessions(self, user_id: int) -> List[str]:
        """Get list of session IDs for user"""
        cache_key = f"{self.user_sessions_prefix}{user_id}"
        return cache.get(cache_key, [])
    
    def _clear_user_sessions(self, user_id: int):
        """Clear all sessions for user"""
        cache_key = f"{self.user_sessions_prefix}{user_id}"
        cache.delete(cache_key)
    
    def _flag_suspicious_session(self, session_id: str, reason: str):
        """Flag session as suspicious"""
        session_data = self._get_session(session_id)
        
        if session_data:
            session_data.setdefault('security_flags', {})
            session_data['security_flags']['suspicious'] = True
            session_data['security_flags']['suspicious_reason'] = reason
            session_data['security_flags']['flagged_at'] = timezone.now().isoformat()
            
            self._store_session(session_id, session_data)
            
            # Log suspicious activity
            user_email = session_data.get('user_email', 'unknown')
            security_logger.error(f"Suspicious session flagged for {user_email}: {reason}")


class SessionMiddleware:
    """
    Middleware to integrate session management with Django requests
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.session_manager = SessionManager()
    
    def __call__(self, request):
        # Add session manager to request
        request.session_manager = self.session_manager
        
        # Process request
        response = self.get_response(request)
        
        return response


# Global session manager instance
session_manager = SessionManager()