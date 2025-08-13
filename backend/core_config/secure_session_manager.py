"""
Enhanced Secure Session Manager
Integrates Redis-backed session storage with SecureUserSession model
"""

import json
import logging
import hashlib
import secrets
import user_agents
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.http import HttpRequest
from django.db import transaction
from authentication.models import SecureUserSession
from core_config.error_handling import security_event_logger

# Security logger
security_logger = logging.getLogger('security')

User = get_user_model()

class SecureSessionManager:
    """
    Enhanced secure session manager with Redis backend and database persistence
    """
    
    # Session configuration
    SESSION_TIMEOUT = timedelta(hours=24)  # Default session timeout
    MAX_SESSIONS_PER_USER = 5  # Maximum concurrent sessions per user
    SESSION_CLEANUP_INTERVAL = timedelta(hours=1)  # Cleanup interval
    
    # Session security settings
    REQUIRE_IP_CONSISTENCY = getattr(settings, 'SESSION_REQUIRE_IP_CONSISTENCY', False)
    REQUIRE_USER_AGENT_CONSISTENCY = getattr(settings, 'SESSION_REQUIRE_USER_AGENT_CONSISTENCY', True)
    ENABLE_SESSION_FINGERPRINTING = getattr(settings, 'SESSION_ENABLE_FINGERPRINTING', True)
    ENABLE_HIJACKING_PROTECTION = getattr(settings, 'SESSION_ENABLE_HIJACKING_PROTECTION', True)
    
    def __init__(self):
        """Initialize secure session manager"""
        self.cache_prefix = 'secure_session:'
        self.user_sessions_prefix = 'user_secure_sessions:'
        self.session_metadata_prefix = 'session_secure_meta:'
    
    def create_session(self, user: User, request: HttpRequest, 
                      jwt_token_id: str = None,
                      additional_data: Dict[str, Any] = None) -> SecureUserSession:
        """
        Create a new secure session for user
        
        Args:
            user: User instance
            request: HTTP request object
            jwt_token_id: JWT token ID for linking
            additional_data: Additional session data
            
        Returns:
            SecureUserSession instance
        """
        # Generate secure session ID
        session_id = self._generate_session_id()
        
        # Get client information
        client_info = self._extract_client_info(request)
        
        # Enforce session limits before creating new session
        self._enforce_session_limits(user)
        
        # Create session in database
        with transaction.atomic():
            session = SecureUserSession.objects.create(
                user=user,
                session_id=session_id,
                jwt_token_id=jwt_token_id or session_id,
                expires_at=timezone.now() + self.SESSION_TIMEOUT,
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                user_agent_hash=client_info['user_agent_hash'],
                session_fingerprint=client_info['session_fingerprint'],
                device_type=client_info['device_type'],
                browser_name=client_info['browser_name'],
                os_name=client_info['os_name'],
                login_method='jwt',
                timezone=client_info.get('timezone', ''),
                login_location=client_info.get('location', ''),
            )
        
        # Create session data for Redis cache
        session_data = {
            'session_id': session_id,
            'user_id': user.id,
            'user_email': user.email,
            'db_session_id': session.id,
            'created_at': session.created_at.isoformat(),
            'last_activity': session.last_activity.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'ip_address': client_info['ip_address'],
            'user_agent_hash': client_info['user_agent_hash'],
            'session_fingerprint': client_info['session_fingerprint'],
            'is_active': True,
            'security_flags': {
                'ip_verified': True,
                'user_agent_verified': True,
                'fingerprint_verified': True,
            }
        }
        
        # Add additional data if provided
        if additional_data:
            session_data.update(additional_data)
        
        # Store session data in Redis for fast access
        self._store_session_cache(session_id, session_data)
        
        # Add to user's session list in cache
        self._add_to_user_sessions_cache(user.id, session_id)
        
        # Log session creation
        security_logger.info(
            f"Secure session created for user {user.email}: {session_id[:8]}... "
            f"from {client_info['ip_address']} ({client_info['device_type']})"
        )
        
        # Log security event
        security_event_logger.log_security_event(
            request, 'session_created', {
                'user_id': user.id,
                'session_id': session_id[:8] + '...',
                'device_type': client_info['device_type'],
                'browser': client_info['browser_name'],
            }
        )
        
        return session
    
    def validate_session(self, session_id: str, request: HttpRequest = None) -> Optional[SecureUserSession]:
        """
        Validate and retrieve session
        
        Args:
            session_id: Session identifier
            request: HTTP request for security validation
            
        Returns:
            SecureUserSession instance if valid, None otherwise
        """
        # Try to get from cache first
        session_data = self._get_session_cache(session_id)
        
        if not session_data:
            # Fallback to database
            try:
                db_session = SecureUserSession.objects.get(
                    session_id=session_id,
                    is_active=True
                )
                
                # Check if expired
                if db_session.is_expired():
                    db_session.invalidate('expired')
                    return None
                
                # Rebuild cache
                session_data = self._session_to_cache_data(db_session)
                self._store_session_cache(session_id, session_data)
                
            except SecureUserSession.DoesNotExist:
                return None
        else:
            # Get database session
            try:
                db_session = SecureUserSession.objects.get(id=session_data['db_session_id'])
                
                # Check if database session is still active
                if not db_session.is_active or db_session.is_expired():
                    self._delete_session_cache(session_id)
                    return None
                    
            except SecureUserSession.DoesNotExist:
                self._delete_session_cache(session_id)
                return None
        
        # Perform security validations if request is provided
        if request and self.ENABLE_HIJACKING_PROTECTION:
            if not self._validate_session_security(db_session, request):
                security_logger.warning(f"Session security validation failed: {session_id[:8]}...")
                db_session.mark_suspicious('security_validation_failed')
                return None
        
        # Update last activity
        db_session.update_activity()
        
        # Update cache
        session_data['last_activity'] = db_session.last_activity.isoformat()
        self._store_session_cache(session_id, session_data)
        
        return db_session
    
    def invalidate_session(self, session_id: str, reason: str = 'user_logout') -> bool:
        """
        Invalidate a specific session
        
        Args:
            session_id: Session identifier
            reason: Reason for invalidation
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get session from database
            db_session = SecureUserSession.objects.get(session_id=session_id)
            
            # Invalidate in database
            db_session.invalidate(reason)
            
            # Remove from cache
            self._delete_session_cache(session_id)
            
            # Remove from user's session list
            self._remove_from_user_sessions_cache(db_session.user_id, session_id)
            
            # Log session invalidation
            security_logger.info(
                f"Secure session invalidated for {db_session.user.email}: "
                f"{session_id[:8]}... (reason: {reason})"
            )
            
            return True
            
        except SecureUserSession.DoesNotExist:
            return False
    
    def invalidate_all_user_sessions(self, user: User, reason: str = 'security_action') -> int:
        """
        Invalidate all sessions for a user
        
        Args:
            user: User instance
            reason: Reason for invalidation
            
        Returns:
            Number of sessions invalidated
        """
        # Get all active sessions for user
        active_sessions = SecureUserSession.get_user_active_sessions(user)
        invalidated_count = 0
        
        for session in active_sessions:
            if self.invalidate_session(session.session_id, reason):
                invalidated_count += 1
        
        # Clear user sessions cache
        self._clear_user_sessions_cache(user.id)
        
        security_logger.warning(
            f"All secure sessions invalidated for user {user.email}: "
            f"{invalidated_count} sessions (reason: {reason})"
        )
        
        return invalidated_count
    
    def get_user_sessions(self, user: User) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user
        
        Args:
            user: User instance
            
        Returns:
            List of session information dictionaries
        """
        active_sessions = SecureUserSession.get_user_active_sessions(user)
        sessions = []
        
        for session in active_sessions:
            session_info = session.get_session_info()
            sessions.append(session_info)
        
        return sessions
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions
        
        Returns:
            Number of sessions cleaned up
        """
        # Clean up database sessions
        cleanup_count = SecureUserSession.cleanup_expired_sessions()
        
        # Clean up cache entries (this would be more complex in production)
        # For now, we rely on Redis TTL for cache cleanup
        
        security_logger.info(f"Secure session cleanup completed: {cleanup_count} sessions cleaned")
        
        return cleanup_count
    
    def get_session_statistics(self) -> Dict[str, Any]:
        """
        Get session statistics
        
        Returns:
            Dictionary with session statistics
        """
        from django.db.models import Count
        
        # Get statistics from database
        total_active = SecureUserSession.objects.filter(
            is_active=True,
            expires_at__gt=timezone.now()
        ).count()
        
        suspicious_count = SecureUserSession.objects.filter(
            is_suspicious=True,
            is_active=True
        ).count()
        
        # Sessions by device type
        device_stats = SecureUserSession.objects.filter(
            is_active=True,
            expires_at__gt=timezone.now()
        ).values('device_type').annotate(count=Count('device_type'))
        
        # Recent logins (last 24 hours)
        recent_logins = SecureUserSession.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        return {
            'total_active_sessions': total_active,
            'suspicious_sessions': suspicious_count,
            'recent_logins': recent_logins,
            'sessions_by_device': {item['device_type']: item['count'] for item in device_stats},
        }
    
    def _generate_session_id(self) -> str:
        """Generate cryptographically secure session ID"""
        return secrets.token_urlsafe(32)
    
    def _extract_client_info(self, request: HttpRequest) -> Dict[str, str]:
        """Extract comprehensive client information from request"""
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        ip_address = self._get_client_ip(request)
        
        # Parse user agent
        user_agent = user_agents.parse(user_agent_string)
        
        # Create user agent hash for comparison
        user_agent_hash = hashlib.sha256(user_agent_string.encode()).hexdigest()
        
        # Create session fingerprint
        fingerprint_data = f"{user_agent_string}{ip_address}"
        session_fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        # Extract device information
        device_type = 'Unknown'
        if user_agent.is_mobile:
            device_type = 'Mobile'
        elif user_agent.is_tablet:
            device_type = 'Tablet'
        elif user_agent.is_pc:
            device_type = 'Desktop'
        elif user_agent.is_bot:
            device_type = 'Bot'
        
        return {
            'ip_address': ip_address,
            'user_agent': user_agent_string,
            'user_agent_hash': user_agent_hash,
            'session_fingerprint': session_fingerprint,
            'device_type': device_type,
            'browser_name': user_agent.browser.family,
            'os_name': user_agent.os.family,
            'timezone': request.META.get('HTTP_TIMEZONE', ''),
            'location': '',  # Would be populated by IP geolocation service
        }
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip
    
    def _validate_session_security(self, session: SecureUserSession, request: HttpRequest) -> bool:
        """Validate session security constraints"""
        client_info = self._extract_client_info(request)
        
        # Check IP consistency
        if self.REQUIRE_IP_CONSISTENCY:
            if session.ip_address != client_info['ip_address']:
                security_logger.warning(
                    f"IP address mismatch for session {session.session_id[:8]}...: "
                    f"{session.ip_address} vs {client_info['ip_address']}"
                )
                return False
        
        # Check user agent consistency
        if self.REQUIRE_USER_AGENT_CONSISTENCY:
            if session.user_agent_hash != client_info['user_agent_hash']:
                security_logger.warning(
                    f"User agent mismatch for session {session.session_id[:8]}..."
                )
                return False
        
        # Check session fingerprint
        if self.ENABLE_SESSION_FINGERPRINTING:
            if session.session_fingerprint != client_info['session_fingerprint']:
                security_logger.warning(
                    f"Session fingerprint mismatch for session {session.session_id[:8]}..."
                )
                return False
        
        return True
    
    def _enforce_session_limits(self, user: User):
        """Enforce maximum session limits per user"""
        excess_count = SecureUserSession.enforce_session_limit(user, self.MAX_SESSIONS_PER_USER)
        
        if excess_count > 0:
            security_logger.info(
                f"Session limit enforced for user {user.email}: "
                f"{excess_count} oldest sessions removed"
            )
    
    def _session_to_cache_data(self, session: SecureUserSession) -> Dict[str, Any]:
        """Convert database session to cache data"""
        return {
            'session_id': session.session_id,
            'user_id': session.user_id,
            'user_email': session.user.email,
            'db_session_id': session.id,
            'created_at': session.created_at.isoformat(),
            'last_activity': session.last_activity.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'ip_address': session.ip_address,
            'user_agent_hash': session.user_agent_hash,
            'session_fingerprint': session.session_fingerprint,
            'is_active': session.is_active,
            'security_flags': {
                'ip_verified': session.ip_verified,
                'user_agent_verified': session.user_agent_verified,
                'fingerprint_verified': session.fingerprint_verified,
            }
        }
    
    # Cache management methods
    def _store_session_cache(self, session_id: str, session_data: Dict[str, Any]):
        """Store session data in Redis cache"""
        cache_key = f"{self.cache_prefix}{session_id}"
        timeout = int(self.SESSION_TIMEOUT.total_seconds())
        cache.set(cache_key, json.dumps(session_data), timeout=timeout)
    
    def _get_session_cache(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data from Redis cache"""
        cache_key = f"{self.cache_prefix}{session_id}"
        data = cache.get(cache_key)
        
        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                security_logger.error(f"Failed to decode session cache data for {session_id[:8]}...")
                return None
        
        return None
    
    def _delete_session_cache(self, session_id: str):
        """Delete session data from Redis cache"""
        cache_key = f"{self.cache_prefix}{session_id}"
        cache.delete(cache_key)
    
    def _add_to_user_sessions_cache(self, user_id: int, session_id: str):
        """Add session to user's session list in cache"""
        cache_key = f"{self.user_sessions_prefix}{user_id}"
        user_sessions = cache.get(cache_key, [])
        
        if session_id not in user_sessions:
            user_sessions.append(session_id)
            # Keep only recent sessions
            user_sessions = user_sessions[-self.MAX_SESSIONS_PER_USER:]
            cache.set(cache_key, user_sessions, timeout=None)
    
    def _remove_from_user_sessions_cache(self, user_id: int, session_id: str):
        """Remove session from user's session list in cache"""
        cache_key = f"{self.user_sessions_prefix}{user_id}"
        user_sessions = cache.get(cache_key, [])
        
        if session_id in user_sessions:
            user_sessions.remove(session_id)
            cache.set(cache_key, user_sessions, timeout=None)
    
    def _clear_user_sessions_cache(self, user_id: int):
        """Clear all sessions for user from cache"""
        cache_key = f"{self.user_sessions_prefix}{user_id}"
        cache.delete(cache_key)


class SecureSessionMiddleware:
    """
    Middleware to integrate secure session management with Django requests
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.session_manager = SecureSessionManager()
    
    def __call__(self, request):
        # Add secure session manager to request
        request.secure_session_manager = self.session_manager
        
        # Process request
        response = self.get_response(request)
        
        return response


# Global secure session manager instance
secure_session_manager = SecureSessionManager()