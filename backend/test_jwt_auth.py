"""
Comprehensive test suite for JWT authentication system
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
from core_config.jwt_auth import SecureTokenManager, JWTAuthentication, SecureCookieManager
from authentication.models import User
from permissions.models import Role
from organization.models import Organization

User = get_user_model()

class TestSecureTokenManager(TestCase):
    """Test cases for SecureTokenManager"""
    
    def setUp(self):
        self.jwt_manager = SecureTokenManager()
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
        tokens = self.jwt_manager.generate_token_pair(self.user, request)
        
        self.assertIn('access_token', tokens)
        self.assertIn('refresh_token', tokens)
        self.assertIn('token_id', tokens)
        
        # Verify tokens are valid JWT
        access_payload = jwt.decode(
            tokens['access_token'], 
            self.jwt_manager.secret_key, 
            algorithms=[self.jwt_manager.ALGORITHM]
        )
        
        refresh_payload = jwt.decode(
            tokens['refresh_token'], 
            self.jwt_manager.refresh_secret_key, 
            algorithms=[self.jwt_manager.ALGORITHM]
        )
        
        # Check payload contents
        self.assertEqual(access_payload['sub'], str(self.user.id))
        self.assertEqual(access_payload['user_email'], self.user.email)
        self.assertEqual(access_payload['token_type'], 'access')
        
        self.assertEqual(refresh_payload['sub'], str(self.user.id))
        self.assertEqual(refresh_payload['token_type'], 'refresh')
    
    def test_token_validation(self):
        """Test JWT token validation"""
        tokens = self.jwt_manager.generate_token_pair(self.user)
        
        # Validate access token
        access_payload = self.jwt_manager.validate_token(
            tokens['access_token'], 
            SecureTokenManager.ACCESS_TOKEN
        )
        
        self.assertEqual(access_payload['user'], self.user)
        self.assertEqual(access_payload['token_type'], 'access')
        
        # Validate refresh token
        refresh_payload = self.jwt_manager.validate_token(
            tokens['refresh_token'], 
            SecureTokenManager.REFRESH_TOKEN
        )
        
        self.assertEqual(refresh_payload['user'], self.user)
        self.assertEqual(refresh_payload['token_type'], 'refresh')
    
    def test_token_refresh(self):
        """Test token refresh functionality"""
        request = self.factory.post('/refresh/')
        tokens = self.jwt_manager.generate_token_pair(self.user, request)
        
        # Refresh tokens
        new_tokens = self.jwt_manager.refresh_token(tokens['refresh_token'], request)
        
        self.assertIn('access_token', new_tokens)
        self.assertIn('refresh_token', new_tokens)
        
        # New tokens should be different
        self.assertNotEqual(tokens['access_token'], new_tokens['access_token'])
        self.assertNotEqual(tokens['refresh_token'], new_tokens['refresh_token'])
        
        # Old refresh token should be blacklisted
        with self.assertRaises(Exception):
            self.jwt_manager.validate_token(
                tokens['refresh_token'], 
                SecureTokenManager.REFRESH_TOKEN
            )
    
    def test_token_revocation(self):
        """Test token revocation"""
        tokens = self.jwt_manager.generate_token_pair(self.user)
        
        # Token should be valid initially
        payload = self.jwt_manager.validate_token(tokens['access_token'])
        self.assertEqual(payload['user'], self.user)
        
        # Revoke token
        self.jwt_manager.revoke_token(tokens['access_token'])
        
        # Token should be invalid after revocation
        with self.assertRaises(Exception):
            self.jwt_manager.validate_token(tokens['access_token'])
    
    def test_revoke_all_user_tokens(self):
        """Test revoking all tokens for a user"""
        # Generate multiple token pairs
        tokens1 = self.jwt_manager.generate_token_pair(self.user)
        tokens2 = self.jwt_manager.generate_token_pair(self.user)
        
        # Both should be valid initially
        self.jwt_manager.validate_token(tokens1['access_token'])
        self.jwt_manager.validate_token(tokens2['access_token'])
        
        # Revoke all tokens
        self.jwt_manager.revoke_all_user_tokens(self.user)
        
        # Both should be invalid after mass revocation
        with self.assertRaises(Exception):
            self.jwt_manager.validate_token(tokens1['access_token'])
        
        with self.assertRaises(Exception):
            self.jwt_manager.validate_token(tokens2['access_token'])
    
    def test_expired_token_validation(self):
        """Test validation of expired tokens"""
        # Create token with very short expiration
        original_lifetime = SecureTokenManager.ACCESS_TOKEN_LIFETIME
        SecureTokenManager.ACCESS_TOKEN_LIFETIME = timedelta(seconds=1)
        
        try:
            tokens = self.jwt_manager.generate_token_pair(self.user)
            
            # Wait for token to expire
            import time
            time.sleep(2)
            
            # Token should be expired
            with self.assertRaises(Exception):
                self.jwt_manager.validate_token(tokens['access_token'])
        
        finally:
            # Restore original lifetime
            SecureTokenManager.ACCESS_TOKEN_LIFETIME = original_lifetime
    
    def test_invalid_token_validation(self):
        """Test validation of invalid tokens"""
        # Test completely invalid token
        with self.assertRaises(Exception):
            self.jwt_manager.validate_token('invalid.token.here')
        
        # Test token with wrong signature
        fake_token = jwt.encode(
            {'sub': str(self.user.id), 'exp': timezone.now() + timedelta(hours=1)},
            'wrong_secret',
            algorithm='HS256'
        )
        
        with self.assertRaises(Exception):
            self.jwt_manager.validate_token(fake_token)


class TestJWTAuthentication(TestCase):
    """Test cases for JWTAuthentication backend"""
    
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


class TestSecureCookieManager(TestCase):
    """Test cases for SecureCookieManager"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.cookie_manager = SecureCookieManager()
        
        self.tokens = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token'
        }
    
    def test_set_auth_cookies(self):
        """Test setting authentication cookies"""
        from django.http import HttpResponse
        
        response = HttpResponse()
        self.cookie_manager.set_auth_cookies(response, self.tokens, secure=False)
        
        # Check that cookies are set
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)
        
        # Check cookie properties
        access_cookie = response.cookies['access_token']
        self.assertEqual(access_cookie.value, self.tokens['access_token'])
        self.assertTrue(access_cookie['httponly'])
        self.assertEqual(access_cookie['samesite'], 'Strict')
    
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


class TestJWTViews(APITestCase):
    """Integration tests for JWT authentication views"""
    
    def setUp(self):
        self.client = APIClient()
        
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
    
    def test_jwt_login_success(self):
        """Test successful JWT login"""
        data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        response = self.client.post('/api/auth/jwt/login/', data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], 'test@example.com')
        
        # Check that cookies are set
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)
    
    def test_jwt_login_invalid_credentials(self):
        """Test JWT login with invalid credentials"""
        data = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }
        
        response = self.client.post('/api/auth/jwt/login/', data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error']['code'], 'AUTHENTICATION_ERROR')
    
    def test_jwt_login_missing_data(self):
        """Test JWT login with missing data"""
        data = {
            'email': 'test@example.com'
            # Missing password
        }
        
        response = self.client.post('/api/auth/jwt/login/', data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error']['code'], 'VALIDATION_ERROR')
    
    def test_jwt_refresh_token(self):
        """Test JWT token refresh"""
        # First login to get tokens
        login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        login_response = self.client.post('/api/auth/jwt/login/', login_data)
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        
        # Extract refresh token from cookies
        refresh_token = login_response.cookies['refresh_token'].value
        
        # Set refresh token cookie for refresh request
        self.client.cookies['refresh_token'] = refresh_token
        
        # Refresh token
        refresh_response = self.client.post('/api/auth/jwt/refresh/')
        
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertTrue(refresh_response.data['success'])
        
        # Check that new cookies are set
        self.assertIn('access_token', refresh_response.cookies)
        self.assertIn('refresh_token', refresh_response.cookies)
        
        # New tokens should be different
        new_access_token = refresh_response.cookies['access_token'].value
        new_refresh_token = refresh_response.cookies['refresh_token'].value
        
        original_access_token = login_response.cookies['access_token'].value
        
        self.assertNotEqual(new_access_token, original_access_token)
        self.assertNotEqual(new_refresh_token, refresh_token)
    
    def test_jwt_logout(self):
        """Test JWT logout"""
        # First login
        login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        login_response = self.client.post('/api/auth/jwt/login/', login_data)
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        
        # Set cookies from login
        access_token = login_response.cookies['access_token'].value
        refresh_token = login_response.cookies['refresh_token'].value
        
        self.client.cookies['access_token'] = access_token
        self.client.cookies['refresh_token'] = refresh_token
        
        # Logout
        logout_response = self.client.post('/api/auth/jwt/logout/')
        
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
        self.assertTrue(logout_response.data['success'])
        
        # Check that cookies are cleared
        self.assertEqual(logout_response.cookies['access_token']['max-age'], 0)
        self.assertEqual(logout_response.cookies['refresh_token']['max-age'], 0)
    
    def test_jwt_user_profile(self):
        """Test getting user profile with JWT authentication"""
        # First login
        login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        login_response = self.client.post('/api/auth/jwt/login/', login_data)
        access_token = login_response.cookies['access_token'].value
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        # Get profile
        profile_response = self.client.get('/api/auth/jwt/profile/')
        
        self.assertEqual(profile_response.status_code, status.HTTP_200_OK)
        self.assertTrue(profile_response.data['success'])
        self.assertIn('user', profile_response.data)
        self.assertEqual(profile_response.data['user']['email'], 'test@example.com')
    
    def test_jwt_change_password(self):
        """Test changing password with JWT authentication"""
        # First login
        login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        login_response = self.client.post('/api/auth/jwt/login/', login_data)
        access_token = login_response.cookies['access_token'].value
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        # Change password
        password_data = {
            'current_password': 'testpass123',
            'new_password': 'newtestpass123456'
        }
        
        password_response = self.client.post('/api/auth/jwt/change-password/', password_data)
        
        self.assertEqual(password_response.status_code, status.HTTP_200_OK)
        self.assertTrue(password_response.data['success'])
        
        # Check that new cookies are set (tokens refreshed)
        self.assertIn('access_token', password_response.cookies)
        self.assertIn('refresh_token', password_response.cookies)
        
        # Verify old password no longer works
        old_login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        old_login_response = self.client.post('/api/auth/jwt/login/', old_login_data)
        self.assertEqual(old_login_response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # Verify new password works
        new_login_data = {
            'email': 'test@example.com',
            'password': 'newtestpass123456'
        }
        
        new_login_response = self.client.post('/api/auth/jwt/login/', new_login_data)
        self.assertEqual(new_login_response.status_code, status.HTTP_200_OK)


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