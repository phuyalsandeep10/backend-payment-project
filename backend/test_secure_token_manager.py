"""
Comprehensive test suite for SecureTokenManager
Tests the enhanced JWT authentication system with security features
"""

import jwt
import json
from datetime import datetime, timedelta
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from core_config.jwt_auth import SecureTokenManager, JWTAuthentication, SecureCookieManager
from authentication.models import User
from permissions.models import Role
from organization.models import Organization

User = get_user_model()

class TestSecureTokenManager(TestCase):
    """Test cases for SecureTokenManager"""
    
    def setUp(self):
        self.token_manager = SecureTokenManager()
        self.factory = RequestFactory()
        
        # Create test organization and role
        self.organization = Organization.objects.create(name='Test Org')
        self.role = Role.objects.create(name='Test Role', organization=self.organization)
        
        # Create test user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            organization=self.organization,
            role=self.role
        )
    
    def test_token_generation(self):
        """Test JWT token pair generation"""
        request = self.factory.post('/login/')
        tokens = self.token_manager.generate_token_pair(self.user, request)
        
        self.assertIn('access_token', tokens)
        self.assertIn('refresh_token', tokens)
        self.assertIn('token_id', tokens)
        
        # Verify tokens are valid JWT
        access_payload = jwt.decode(
            tokens['access_token'], 
            self.token_manager.secret_key, 
            algorithms=[self.token_manager.ALGORITHM]
        )
        
        refresh_payload = jwt.decode(
            tokens['refresh_token'], 
            self.token_manager.refresh_secret_key, 
            algorithms=[self.token_manager.ALGORITHM]
        )
        
        # Check payload contents
        self.assertEqual(access_payload['sub'], str(self.user.id))
        self.assertEqual(access_payload['user_email'], self.user.email)
        self.assertEqual(access_payload['token_type'], 'access')
        self.assertEqual(access_payload['iss'], 'prs-backend')
        
        self.assertEqual(refresh_payload['sub'], str(self.user.id))
        self.assertEqual(refresh_payload['token_type'], 'refresh')
        self.assertEqual(refresh_payload['iss'], 'prs-backend')
    
    def test_token_validation_enhanced_security(self):
        """Test enhanced JWT token validation with security checks"""
        request = self.factory.post('/login/')
        tokens = self.token_manager.generate_token_pair(self.user, request)
        
        # Validate access token with request context
        access_payload = self.token_manager.validate_token(
            tokens['access_token'], 
            SecureTokenManager.ACCESS_TOKEN,
            request
        )
        
        self.assertEqual(access_payload['user'], self.user)
        self.assertEqual(access_payload['token_type'], 'access')
        
        # Validate refresh token
        refresh_payload = self.token_manager.validate_token(
            tokens['refresh_token'], 
            SecureTokenManager.REFRESH_TOKEN,
            request
        )
        
        self.assertEqual(refresh_payload['user'], self.user)
        self.assertEqual(refresh_payload['token_type'], 'refresh')
    
    def test_invalid_token_format_validation(self):
        """Test validation of invalid token formats"""
        request = self.factory.post('/test/')
        
        # Test empty token
        with self.assertRaises(AuthenticationFailed) as context:
            self.token_manager.validate_token('', request=request)
        self.assertIn('Invalid token format', str(context.exception))
        
        # Test malformed token (not 3 parts)
        with self.assertRaises(AuthenticationFailed) as context:
            self.token_manager.validate_token('invalid.token', request=request)
        self.assertIn('Invalid token format', str(context.exception))
        
        # Test completely invalid token
        with self.assertRaises(AuthenticationFailed):
            self.token_manager.validate_token('invalid.token.here', request=request)
    
    def test_token_age_validation(self):
        """Test validation of token age"""
        # Create a token with a very old issued time
        now = timezone.now()
        old_time = now - timedelta(days=30)  # 30 days old
        
        payload = {
            'iss': self.token_manager.ISSUER,
            'sub': str(self.user.id),
            'iat': int(old_time.timestamp()),
            'exp': int((now + timedelta(hours=1)).timestamp()),
            'jti': 'test_token_id',
            'token_type': 'access',
            'user_email': self.user.email,
            'token_version': 0,
        }
        
        old_token = jwt.encode(payload, self.token_manager.secret_key, algorithm=self.token_manager.ALGORITHM)
        
        request = self.factory.post('/test/')
        with self.assertRaises(AuthenticationFailed) as context:
            self.token_manager.validate_token(old_token, request=request)
        self.assertIn('Token is too old', str(context.exception))
    
    def test_token_refresh_with_blacklisting(self):
        """Test token refresh functionality with proper blacklisting"""
        request = self.factory.post('/refresh/')
        tokens = self.token_manager.generate_token_pair(self.user, request)
        
        # Refresh tokens
        new_tokens = self.token_manager.refresh_token(tokens['refresh_token'], request)
        
        self.assertIn('access_token', new_tokens)
        self.assertIn('refresh_token', new_tokens)
        
        # New tokens should be different
        self.assertNotEqual(tokens['access_token'], new_tokens['access_token'])
        self.assertNotEqual(tokens['refresh_token'], new_tokens['refresh_token'])
        
        # Old refresh token should be blacklisted
        with self.assertRaises(AuthenticationFailed):
            self.token_manager.validate_token(
                tokens['refresh_token'], 
                SecureTokenManager.REFRESH_TOKEN
            )
    
    def test_token_revocation(self):
        """Test individual token revocation"""
        tokens = self.token_manager.generate_token_pair(self.user)
        
        # Token should be valid initially
        payload = self.token_manager.validate_token(tokens['access_token'])
        self.assertEqual(payload['user'], self.user)
        
        # Revoke token
        self.token_manager.revoke_token(tokens['access_token'])
        
        # Token should be invalid after revocation
        with self.assertRaises(AuthenticationFailed):
            self.token_manager.validate_token(tokens['access_token'])
    
    def test_revoke_all_user_tokens(self):
        """Test revoking all tokens for a user"""
        # Generate multiple token pairs
        tokens1 = self.token_manager.generate_token_pair(self.user)
        tokens2 = self.token_manager.generate_token_pair(self.user)
        
        # Both should be valid initially
        self.token_manager.validate_token(tokens1['access_token'])
        self.token_manager.validate_token(tokens2['access_token'])
        
        # Revoke all tokens
        self.token_manager.revoke_all_user_tokens(self.user)
        
        # Both should be invalid after mass revocation
        with self.assertRaises(AuthenticationFailed):
            self.token_manager.validate_token(tokens1['access_token'])
        
        with self.assertRaises(AuthenticationFailed):
            self.token_manager.validate_token(tokens2['access_token'])
    
    def test_token_metadata_storage(self):
        """Test token metadata storage and retrieval"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Test Browser'
        
        tokens = self.token_manager.generate_token_pair(self.user, request)
        
        # Get token metadata
        metadata = self.token_manager.get_token_metadata(tokens['token_id'])
        
        self.assertEqual(metadata['user_id'], self.user.id)
        self.assertEqual(metadata['user_email'], self.user.email)
        self.assertEqual(metadata['ip_address'], '192.168.1.1')
        self.assertEqual(metadata['user_agent'], 'Test Browser')
        self.assertIn('created_at', metadata)
    
    def test_request_context_validation(self):
        """Test request context validation for security"""
        # Create token with specific IP
        request1 = self.factory.post('/login/')
        request1.META['REMOTE_ADDR'] = '192.168.1.1'
        
        tokens = self.token_manager.generate_token_pair(self.user, request1)
        
        # Validate with same IP (should work)
        request2 = self.factory.post('/api/')
        request2.META['REMOTE_ADDR'] = '192.168.1.1'
        
        payload = self.token_manager.validate_token(
            tokens['access_token'], 
            SecureTokenManager.ACCESS_TOKEN,
            request2
        )
        self.assertEqual(payload['user'], self.user)
        
        # Validate with different IP (should log warning but still work)
        request3 = self.factory.post('/api/')
        request3.META['REMOTE_ADDR'] = '192.168.1.2'
        
        # This should still work but log a warning
        payload = self.token_manager.validate_token(
            tokens['access_token'], 
            SecureTokenManager.ACCESS_TOKEN,
            request3
        )
        self.assertEqual(payload['user'], self.user)
    
    def test_expired_token_validation(self):
        """Test validation of expired tokens"""
        # Create token with very short expiration
        original_lifetime = SecureTokenManager.ACCESS_TOKEN_LIFETIME
        SecureTokenManager.ACCESS_TOKEN_LIFETIME = timedelta(seconds=1)
        
        try:
            tokens = self.token_manager.generate_token_pair(self.user)
            
            # Wait for token to expire
            import time
            time.sleep(2)
            
            # Token should be expired
            with self.assertRaises(AuthenticationFailed) as context:
                self.token_manager.validate_token(tokens['access_token'])
            self.assertIn('Token has expired', str(context.exception))
        
        finally:
            # Restore original lifetime
            SecureTokenManager.ACCESS_TOKEN_LIFETIME = original_lifetime
    
    def test_token_version_mismatch(self):
        """Test token validation with version mismatch"""
        tokens = self.token_manager.generate_token_pair(self.user)
        
        # Token should be valid initially
        payload = self.token_manager.validate_token(tokens['access_token'])
        self.assertEqual(payload['user'], self.user)
        
        # Increment user token version (simulating forced logout)
        self.token_manager._increment_user_token_version(self.user)
        
        # Token should now be invalid due to version mismatch
        with self.assertRaises(AuthenticationFailed) as context:
            self.token_manager.validate_token(tokens['access_token'])
        self.assertIn('Token version mismatch', str(context.exception))
    
    def test_inactive_user_validation(self):
        """Test token validation with inactive user"""
        tokens = self.token_manager.generate_token_pair(self.user)
        
        # Token should be valid initially
        payload = self.token_manager.validate_token(tokens['access_token'])
        self.assertEqual(payload['user'], self.user)
        
        # Deactivate user
        self.user.is_active = False
        self.user.save()
        
        # Token should now be invalid
        with self.assertRaises(AuthenticationFailed) as context:
            self.token_manager.validate_token(tokens['access_token'])
        self.assertIn('User not found or inactive', str(context.exception))


class TestJWTAuthenticationBackend(TestCase):
    """Test cases for JWTAuthentication backend with SecureTokenManager"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.auth_backend = JWTAuthentication()
        
        # Create test user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        # Generate tokens
        self.tokens = self.auth_backend.jwt_manager.generate_token_pair(self.user)
    
    def test_authentication_with_bearer_token(self):
        """Test authentication using Bearer token in Authorization header"""
        request = self.factory.get('/api/test/')
        request.META['HTTP_AUTHORIZATION'] = f'Bearer {self.tokens["access_token"]}'
        
        result = self.auth_backend.authenticate(request)
        
        self.assertIsNotNone(result)
        user, token = result
        self.assertEqual(user, self.user)
        self.assertEqual(token, self.tokens['access_token'])
    
    def test_authentication_with_cookie(self):
        """Test authentication using httpOnly cookie"""
        request = self.factory.get('/api/test/')
        request.COOKIES['access_token'] = self.tokens['access_token']
        
        result = self.auth_backend.authenticate(request)
        
        self.assertIsNotNone(result)
        user, token = result
        self.assertEqual(user, self.user)
        self.assertEqual(token, self.tokens['access_token'])
    
    def test_authentication_without_token(self):
        """Test authentication without token"""
        request = self.factory.get('/api/test/')
        
        result = self.auth_backend.authenticate(request)
        
        self.assertIsNone(result)
    
    def test_authentication_with_invalid_token(self):
        """Test authentication with invalid token"""
        request = self.factory.get('/api/test/')
        request.META['HTTP_AUTHORIZATION'] = 'Bearer invalid.token.here'
        
        result = self.auth_backend.authenticate(request)
        
        self.assertIsNone(result)
    
    def test_authentication_with_expired_token(self):
        """Test authentication with expired token"""
        # Create token with very short expiration
        original_lifetime = SecureTokenManager.ACCESS_TOKEN_LIFETIME
        SecureTokenManager.ACCESS_TOKEN_LIFETIME = timedelta(seconds=1)
        
        try:
            expired_tokens = self.auth_backend.jwt_manager.generate_token_pair(self.user)
            
            # Wait for token to expire
            import time
            time.sleep(2)
            
            request = self.factory.get('/api/test/')
            request.META['HTTP_AUTHORIZATION'] = f'Bearer {expired_tokens["access_token"]}'
            
            result = self.auth_backend.authenticate(request)
            
            # Should return None for expired token
            self.assertIsNone(result)
        
        finally:
            # Restore original lifetime
            SecureTokenManager.ACCESS_TOKEN_LIFETIME = original_lifetime


class TestSecureCookieManagerEnhanced(TestCase):
    """Enhanced test cases for SecureCookieManager"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.cookie_manager = SecureCookieManager()
        
        self.tokens = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token'
        }
    
    def test_set_auth_cookies_secure(self):
        """Test setting authentication cookies with secure flag"""
        from django.http import HttpResponse
        
        response = HttpResponse()
        self.cookie_manager.set_auth_cookies(response, self.tokens, secure=True)
        
        # Check that cookies are set with secure flag
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)
        
        # Check cookie security properties
        access_cookie = response.cookies['access_token']
        self.assertEqual(access_cookie.value, self.tokens['access_token'])
        self.assertTrue(access_cookie['httponly'])
        self.assertTrue(access_cookie['secure'])
        self.assertEqual(access_cookie['samesite'], 'Strict')
        
        refresh_cookie = response.cookies['refresh_token']
        self.assertEqual(refresh_cookie.value, self.tokens['refresh_token'])
        self.assertTrue(refresh_cookie['httponly'])
        self.assertTrue(refresh_cookie['secure'])
        self.assertEqual(refresh_cookie['samesite'], 'Strict')
    
    def test_set_auth_cookies_non_secure(self):
        """Test setting authentication cookies without secure flag"""
        from django.http import HttpResponse
        
        response = HttpResponse()
        self.cookie_manager.set_auth_cookies(response, self.tokens, secure=False)
        
        # Check that cookies are set without secure flag
        access_cookie = response.cookies['access_token']
        self.assertFalse(access_cookie['secure'])
        
        refresh_cookie = response.cookies['refresh_token']
        self.assertFalse(refresh_cookie['secure'])
    
    def test_clear_auth_cookies(self):
        """Test clearing authentication cookies"""
        from django.http import HttpResponse
        
        response = HttpResponse()
        
        # First set cookies
        self.cookie_manager.set_auth_cookies(response, self.tokens, secure=False)
        
        # Then clear them
        self.cookie_manager.clear_auth_cookies(response)
        
        # Check that cookies are cleared (max_age=0)
        access_cookie = response.cookies['access_token']
        refresh_cookie = response.cookies['refresh_token']
        
        self.assertEqual(access_cookie['max-age'], 0)
        self.assertEqual(refresh_cookie['max-age'], 0)
    
    def test_get_refresh_token_from_cookies(self):
        """Test getting refresh token from cookies"""
        request = self.factory.get('/api/test/')
        request.COOKIES['refresh_token'] = self.tokens['refresh_token']
        
        token = self.cookie_manager.get_refresh_token_from_cookies(request)
        
        self.assertEqual(token, self.tokens['refresh_token'])
    
    def test_get_refresh_token_missing(self):
        """Test getting refresh token when cookie is missing"""
        request = self.factory.get('/api/test/')
        
        token = self.cookie_manager.get_refresh_token_from_cookies(request)
        
        self.assertIsNone(token)


if __name__ == '__main__':
    # Run tests
    import django
    from django.conf import settings
    from django.test.utils import get_runner
    
    if not settings.configured:
        settings.configure(
            DEBUG=True,
            DATABASES={
                'default': {
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': ':memory:',
                }
            },
            INSTALLED_APPS=[
                'django.contrib.auth',
                'django.contrib.contenttypes',
                'rest_framework',
                'authentication',
                'permissions',
                'organization',
                'core_config',
            ],
            SECRET_KEY='test-secret-key',
            USE_TZ=True,
            AUTH_USER_MODEL='authentication.User',
            CACHES={
                'default': {
                    'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
                }
            },
        )
    
    django.setup()
    
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(['__main__'])
    
    if failures:
        exit(1)