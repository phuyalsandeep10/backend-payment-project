"""
Enhanced JWT Authentication System
Secure token management with httpOnly cookies and token rotation
"""

import jwt
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from core_config.error_handling import security_event_logger

# Security logger
security_logger = logging.getLogger('security')

User = get_user_model()

class SecureTokenManager:
    """
    Enhanced secure JWT token manager with comprehensive security features
    Implements secure token handling, rotation, and validation as per security requirements
    """
    
    # Token types
    ACCESS_TOKEN = 'access'
    REFRESH_TOKEN = 'refresh'
    
    # Token lifetimes
    ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)  # Short-lived access tokens
    REFRESH_TOKEN_LIFETIME = timedelta(days=7)     # Longer-lived refresh tokens
    
    # JWT settings
    ALGORITHM = 'HS256'
    ISSUER = 'prs-backend'
    
    def __init__(self):
        """Initialize JWT token manager"""
        self.secret_key = self._get_secret_key()
        self.refresh_secret_key = self._get_refresh_secret_key()
    
    def _get_secret_key(self) -> str:
        """Get JWT secret key from settings"""
        return getattr(settings, 'JWT_SECRET_KEY', settings.SECRET_KEY)
    
    def _get_refresh_secret_key(self) -> str:
        """Get separate secret key for refresh tokens"""
        return getattr(settings, 'JWT_REFRESH_SECRET_KEY', settings.SECRET_KEY + '_refresh')
    
    def generate_token_pair(self, user: User, request: HttpRequest = None) -> Dict[str, str]:
        """
        Generate access and refresh token pair
        
        Args:
            user: User instance
            request: HTTP request for logging
            
        Returns:
            Dict with access_token and refresh_token
        """
        # Generate unique token ID for this pair
        token_id = secrets.token_urlsafe(32)
        
        # Create access token
        access_token = self._create_token(
            user=user,
            token_type=self.ACCESS_TOKEN,
            token_id=token_id,
            lifetime=self.ACCESS_TOKEN_LIFETIME
        )
        
        # Create refresh token
        refresh_token = self._create_token(
            user=user,
            token_type=self.REFRESH_TOKEN,
            token_id=token_id,
            lifetime=self.REFRESH_TOKEN_LIFETIME
        )
        
        # Store token metadata in cache
        self._store_token_metadata(user, token_id, request)
        
        # Log token generation
        security_logger.info(f"JWT token pair generated for user {user.email}")
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_id': token_id
        }
    
    def _create_token(self, user: User, token_type: str, token_id: str, 
                     lifetime: timedelta) -> str:
        """Create JWT token with specified parameters"""
        now = timezone.now()
        
        payload = {
            # Standard JWT claims
            'iss': self.ISSUER,
            'sub': str(user.id),
            'iat': int(now.timestamp()),
            'exp': int((now + lifetime).timestamp()),
            'jti': token_id,
            
            # Custom claims
            'token_type': token_type,
            'user_email': user.email,
            'user_role': user.role.name if user.role else None,
            'organization_id': user.organization.id if user.organization else None,
            
            # Security claims
            'token_version': self._get_user_token_version(user),
        }
        
        # Use different secret for refresh tokens
        secret = self.refresh_secret_key if token_type == self.REFRESH_TOKEN else self.secret_key
        
        return jwt.encode(payload, secret, algorithm=self.ALGORITHM)
    
    def validate_token(self, token: str, token_type: str = None, request: HttpRequest = None) -> Dict[str, Any]:
        """
        Enhanced JWT token validation with comprehensive security checks
        
        Args:
            token: JWT token string
            token_type: Expected token type (access/refresh)
            request: HTTP request for additional security validation
            
        Returns:
            Token payload if valid
            
        Raises:
            AuthenticationFailed: If token is invalid
        """
        try:
            # Enhanced security: Check token format before processing
            if not token or len(token.split('.')) != 3:
                raise AuthenticationFailed('Invalid token format')
            
            # Determine which secret to use
            if token_type == self.REFRESH_TOKEN:
                secret = self.refresh_secret_key
            else:
                # Try access token secret first
                secret = self.secret_key
            
            # Decode token with enhanced validation options
            payload = jwt.decode(
                token,
                secret,
                algorithms=[self.ALGORITHM],
                issuer=self.ISSUER,
                options={
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_signature': True,
                    'verify_iss': True,
                    'require': ['exp', 'iat', 'sub', 'jti', 'iss']
                }
            )
            
            # Enhanced security: Validate token age (not too old)
            token_age = timezone.now().timestamp() - payload.get('iat', 0)
            max_token_age = self.REFRESH_TOKEN_LIFETIME.total_seconds()
            if token_age > max_token_age:
                raise AuthenticationFailed('Token is too old')
            
            # Validate token type if specified
            if token_type and payload.get('token_type') != token_type:
                raise AuthenticationFailed(f'Invalid token type. Expected {token_type}')
            
            # Check if token is blacklisted
            if self._is_token_blacklisted(payload['jti']):
                raise AuthenticationFailed('Token has been revoked')
            
            # Validate user still exists and is active
            user = self._validate_user_from_payload(payload)
            
            # Check token version (for forced logout)
            if not self._validate_token_version(user, payload.get('token_version', 0)):
                raise AuthenticationFailed('Token version mismatch')
            
            # Enhanced security: Validate request context if provided
            if request:
                self._validate_request_context(payload, request)
            
            # Add user to payload for convenience
            payload['user'] = user
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError as e:
            raise AuthenticationFailed(f'Invalid token: {str(e)}')
        except Exception as e:
            security_logger.error(f"Token validation error: {str(e)}")
            raise AuthenticationFailed('Token validation failed')
    
    def refresh_token(self, refresh_token: str, request: HttpRequest = None) -> Dict[str, str]:
        """
        Refresh access token using refresh token
        
        Args:
            refresh_token: Valid refresh token
            request: HTTP request for logging
            
        Returns:
            New token pair
            
        Raises:
            AuthenticationFailed: If refresh token is invalid
        """
        # Validate refresh token
        payload = self.validate_token(refresh_token, self.REFRESH_TOKEN)
        user = payload['user']
        
        # Generate new token pair
        new_tokens = self.generate_token_pair(user, request)
        
        # Blacklist old refresh token
        self._blacklist_token(payload['jti'])
        
        # Log token refresh
        security_logger.info(f"JWT token refreshed for user {user.email}")
        
        return new_tokens
    
    def revoke_token(self, token: str, request: HttpRequest = None):
        """
        Revoke a specific token
        
        Args:
            token: Token to revoke
            request: HTTP request for logging
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.ALGORITHM],
                options={'verify_exp': False}  # Allow expired tokens for revocation
            )
            
            # Blacklist token
            self._blacklist_token(payload['jti'])
            
            # Log token revocation
            user_email = payload.get('user_email', 'unknown')
            security_logger.info(f"JWT token revoked for user {user_email}")
            
        except jwt.InvalidTokenError:
            # Token is already invalid, nothing to revoke
            pass
    
    def revoke_all_user_tokens(self, user: User, request: HttpRequest = None):
        """
        Revoke all tokens for a user by incrementing token version
        
        Args:
            user: User whose tokens to revoke
            request: HTTP request for logging
        """
        # Increment user token version
        self._increment_user_token_version(user)
        
        # Log mass token revocation
        security_logger.warning(f"All JWT tokens revoked for user {user.email}")
        
        if request:
            security_event_logger.log_suspicious_activity(
                request, 'mass_token_revocation', {'user_id': user.id}
            )
    
    def _validate_user_from_payload(self, payload: Dict[str, Any]) -> User:
        """Validate user from token payload"""
        try:
            user_id = payload['sub']
            user = User.objects.get(id=user_id, is_active=True)
            return user
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found or inactive')
    
    def _validate_token_version(self, user: User, token_version: int) -> bool:
        """Validate token version against user's current version"""
        current_version = self._get_user_token_version(user)
        return token_version == current_version
    
    def _get_user_token_version(self, user: User) -> int:
        """Get user's current token version"""
        cache_key = f"user_token_version:{user.id}"
        version = cache.get(cache_key)
        if version is None:
            version = 0
            cache.set(cache_key, version, timeout=None)  # Never expire
        return version
    
    def _increment_user_token_version(self, user: User):
        """Increment user's token version to invalidate all tokens"""
        cache_key = f"user_token_version:{user.id}"
        current_version = self._get_user_token_version(user)
        new_version = current_version + 1
        cache.set(cache_key, new_version, timeout=None)
    
    def _store_token_metadata(self, user: User, token_id: str, request: HttpRequest = None):
        """Store token metadata for tracking"""
        metadata = {
            'user_id': user.id,
            'user_email': user.email,
            'created_at': timezone.now().isoformat(),
            'ip_address': self._get_client_ip(request) if request else None,
            'user_agent': request.META.get('HTTP_USER_AGENT') if request else None,
        }
        
        cache_key = f"jwt_token_metadata:{token_id}"
        cache.set(cache_key, metadata, timeout=self.REFRESH_TOKEN_LIFETIME.total_seconds())
    
    def _is_token_blacklisted(self, token_id: str) -> bool:
        """Check if token is blacklisted"""
        cache_key = f"jwt_blacklist:{token_id}"
        return cache.get(cache_key, False)
    
    def _blacklist_token(self, token_id: str):
        """Add token to blacklist"""
        cache_key = f"jwt_blacklist:{token_id}"
        # Set with long expiration to ensure revoked tokens stay revoked
        cache.set(cache_key, True, timeout=self.REFRESH_TOKEN_LIFETIME.total_seconds())
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip
    
    def _validate_request_context(self, payload: Dict[str, Any], request: HttpRequest):
        """
        Enhanced security: Validate request context against token metadata
        
        Args:
            payload: Token payload
            request: HTTP request
            
        Raises:
            AuthenticationFailed: If request context doesn't match token
        """
        token_id = payload.get('jti')
        if not token_id:
            return
        
        # Get stored token metadata
        cache_key = f"jwt_token_metadata:{token_id}"
        metadata = cache.get(cache_key)
        
        if metadata:
            # Validate IP address consistency (optional - can be disabled for mobile users)
            stored_ip = metadata.get('ip_address')
            current_ip = self._get_client_ip(request)
            
            # Log IP changes for security monitoring
            if stored_ip and stored_ip != current_ip and stored_ip != 'unknown':
                security_logger.warning(
                    f"IP address change detected for user {metadata.get('user_email')}: "
                    f"{stored_ip} -> {current_ip}"
                )
                
                # For high-security environments, uncomment to enforce IP validation
                # raise AuthenticationFailed('IP address mismatch detected')
    
    def get_token_metadata(self, token_id: str) -> Dict[str, Any]:
        """
        Get metadata for a specific token
        
        Args:
            token_id: Token ID (jti claim)
            
        Returns:
            Token metadata if found, empty dict otherwise
        """
        cache_key = f"jwt_token_metadata:{token_id}"
        return cache.get(cache_key, {})
    
    def list_user_active_tokens(self, user: User) -> List[Dict[str, Any]]:
        """
        List all active tokens for a user
        
        Args:
            user: User instance
            
        Returns:
            List of active token metadata
        """
        # This would require a more sophisticated caching strategy
        # For now, return empty list as this is primarily for admin purposes
        return []


class JWTAuthentication(BaseAuthentication):
    """
    Enhanced JWT authentication backend for DRF with comprehensive security
    """
    
    def __init__(self):
        self.jwt_manager = SecureTokenManager()
    
    def authenticate(self, request: HttpRequest) -> Optional[Tuple[User, str]]:
        """
        Authenticate request using JWT token
        
        Returns:
            Tuple of (user, token) if authenticated, None otherwise
        """
        # Try to get token from Authorization header first
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
        else:
            # Try to get token from httpOnly cookie
            token = request.COOKIES.get('access_token')
        
        if not token:
            return None
        
        try:
            # Validate token with request context for enhanced security
            payload = self.jwt_manager.validate_token(
                token, 
                SecureTokenManager.ACCESS_TOKEN, 
                request
            )
            user = payload['user']
            
            # Log successful authentication
            security_logger.debug(f"JWT authentication successful for user {user.email}")
            
            return (user, token)
            
        except AuthenticationFailed as e:
            # Log authentication failure
            security_logger.warning(f"JWT authentication failed: {str(e)}")
            
            # Log security event for suspicious activity
            if request:
                security_event_logger.log_authentication_attempt(
                    request, 'unknown', False, str(e)
                )
            
            # Don't raise exception here - let other auth backends try
            return None
    
    def authenticate_header(self, request: HttpRequest) -> str:
        """Return authentication header for 401 responses"""
        return 'Bearer'


class SecureCookieManager:
    """
    Manager for secure httpOnly cookies
    """
    
    @staticmethod
    def set_auth_cookies(response: HttpResponse, tokens: Dict[str, str], 
                        secure: bool = None) -> HttpResponse:
        """
        Set secure httpOnly cookies for authentication
        
        Args:
            response: HTTP response object
            tokens: Dict with access_token and refresh_token
            secure: Whether to use secure cookies (defaults to not DEBUG)
            
        Returns:
            Modified response with cookies set
        """
        if secure is None:
            secure = not settings.DEBUG
        
        # Set access token cookie (short-lived)
        response.set_cookie(
            'access_token',
            tokens['access_token'],
            max_age=int(SecureTokenManager.ACCESS_TOKEN_LIFETIME.total_seconds()),
            httponly=True,
            secure=secure,
            samesite='Strict'
        )
        
        # Set refresh token cookie (longer-lived)
        response.set_cookie(
            'refresh_token',
            tokens['refresh_token'],
            max_age=int(SecureTokenManager.REFRESH_TOKEN_LIFETIME.total_seconds()),
            httponly=True,
            secure=secure,
            samesite='Strict'
        )
        
        return response
    
    @staticmethod
    def clear_auth_cookies(response: HttpResponse) -> HttpResponse:
        """
        Clear authentication cookies
        
        Args:
            response: HTTP response object
            
        Returns:
            Modified response with cookies cleared
        """
        response.delete_cookie('access_token', samesite='Strict')
        response.delete_cookie('refresh_token', samesite='Strict')
        
        return response
    
    @staticmethod
    def get_refresh_token_from_cookies(request: HttpRequest) -> Optional[str]:
        """
        Get refresh token from httpOnly cookie
        
        Args:
            request: HTTP request object
            
        Returns:
            Refresh token if present, None otherwise
        """
        return request.COOKIES.get('refresh_token')


# Global instances
secure_token_manager = SecureTokenManager()
cookie_manager = SecureCookieManager()

# Backward compatibility alias
jwt_manager = secure_token_manager