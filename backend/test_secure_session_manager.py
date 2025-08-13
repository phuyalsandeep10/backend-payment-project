"""
Comprehensive test suite for SecureSessionManager
Tests the enhanced session management system with Redis backend and database persistence
"""

import json
from datetime import datetime, timedelta
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from core_config.secure_session_manager import SecureSessionManager
from authentication.models import SecureUserSession
from permissions.models import Role
from organization.models import Organization

User = get_user_model()

class TestSecureSessionManager(TestCase):
    """Test cases for SecureSessionManager"""
    
    def setUp(self):
        self.session_manager = SecureSessionManager()
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
    
    def tearDown(self):
        # Clean up cache
        cache.clear()
        # Clean up database
        SecureUserSession.objects.all().delete()
    
    def test_session_creation(self):
        """Test secure session creation"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        session = self.session_manager.create_session(
            user=self.user,
            request=request,
            jwt_token_id='test_token_id'
        )
        
        # Verify session was created
        self.assertIsInstance(session, SecureUserSession)
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.jwt_token_id, 'test_token_id')
        self.assertEqual(session.ip_address, '192.168.1.1')
        self.assertTrue(session.is_active)
        self.assertFalse(session.is_suspicious)
        
        # Verify session is in database
        db_session = SecureUserSession.objects.get(session_id=session.session_id)
        self.assertEqual(db_session.user, self.user)
        
        # Verify session is in cache
        cache_data = self.session_manager._get_session_cache(session.session_id)
        self.assertIsNotNone(cache_data)
        self.assertEqual(cache_data['user_id'], self.user.id)
    
    def test_session_validation(self):
        """Test session validation"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Create session
        session = self.session_manager.create_session(
            user=self.user,
            request=request
        )
        
        # Validate session
        validated_session = self.session_manager.validate_session(
            session.session_id,
            request
        )
        
        self.assertIsNotNone(validated_session)
        self.assertEqual(validated_session.user, self.user)
        self.assertTrue(validated_session.is_active)
    
    def test_session_validation_with_different_ip(self):
        """Test session validation with different IP address"""
        # Create session with one IP
        request1 = self.factory.post('/login/')
        request1.META['REMOTE_ADDR'] = '192.168.1.1'
        request1.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        session = self.session_manager.create_session(
            user=self.user,
            request=request1
        )
        
        # Try to validate with different IP
        request2 = self.factory.get('/api/')
        request2.META['REMOTE_ADDR'] = '192.168.1.2'
        request2.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # With IP consistency disabled (default), this should still work
        validated_session = self.session_manager.validate_session(
            session.session_id,
            request2
        )
        
        self.assertIsNotNone(validated_session)
        
        # Enable IP consistency checking
        self.session_manager.REQUIRE_IP_CONSISTENCY = True
        
        # Now validation should fail
        validated_session = self.session_manager.validate_session(
            session.session_id,
            request2
        )
        
        self.assertIsNone(validated_session)
        
        # Reset for other tests
        self.session_manager.REQUIRE_IP_CONSISTENCY = False
    
    def test_session_validation_with_different_user_agent(self):
        """Test session validation with different user agent"""
        # Create session with one user agent
        request1 = self.factory.post('/login/')
        request1.META['REMOTE_ADDR'] = '192.168.1.1'
        request1.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        session = self.session_manager.create_session(
            user=self.user,
            request=request1
        )
        
        # Try to validate with different user agent
        request2 = self.factory.get('/api/')
        request2.META['REMOTE_ADDR'] = '192.168.1.1'
        request2.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        
        # With user agent consistency enabled (default), this should fail
        validated_session = self.session_manager.validate_session(
            session.session_id,
            request2
        )
        
        self.assertIsNone(validated_session)
    
    def test_session_expiration(self):
        """Test session expiration"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Create session with short expiration
        original_timeout = self.session_manager.SESSION_TIMEOUT
        self.session_manager.SESSION_TIMEOUT = timedelta(seconds=1)
        
        try:
            session = self.session_manager.create_session(
                user=self.user,
                request=request
            )
            
            # Session should be valid initially
            validated_session = self.session_manager.validate_session(session.session_id)
            self.assertIsNotNone(validated_session)
            
            # Wait for expiration
            import time
            time.sleep(2)
            
            # Session should be expired now
            validated_session = self.session_manager.validate_session(session.session_id)
            self.assertIsNone(validated_session)
            
            # Check database session is marked inactive
            db_session = SecureUserSession.objects.get(session_id=session.session_id)
            self.assertFalse(db_session.is_active)
            
        finally:
            # Restore original timeout
            self.session_manager.SESSION_TIMEOUT = original_timeout
    
    def test_session_invalidation(self):
        """Test session invalidation"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        session = self.session_manager.create_session(
            user=self.user,
            request=request
        )
        
        # Session should be valid initially
        validated_session = self.session_manager.validate_session(session.session_id)
        self.assertIsNotNone(validated_session)
        
        # Invalidate session
        success = self.session_manager.invalidate_session(session.session_id, 'test_invalidation')
        self.assertTrue(success)
        
        # Session should be invalid now
        validated_session = self.session_manager.validate_session(session.session_id)
        self.assertIsNone(validated_session)
        
        # Check database session is marked inactive
        db_session = SecureUserSession.objects.get(session_id=session.session_id)
        self.assertFalse(db_session.is_active)
    
    def test_invalidate_all_user_sessions(self):
        """Test invalidating all sessions for a user"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Create multiple sessions
        session1 = self.session_manager.create_session(user=self.user, request=request)
        session2 = self.session_manager.create_session(user=self.user, request=request)
        session3 = self.session_manager.create_session(user=self.user, request=request)
        
        # All sessions should be valid initially
        self.assertIsNotNone(self.session_manager.validate_session(session1.session_id))
        self.assertIsNotNone(self.session_manager.validate_session(session2.session_id))
        self.assertIsNotNone(self.session_manager.validate_session(session3.session_id))
        
        # Invalidate all user sessions
        invalidated_count = self.session_manager.invalidate_all_user_sessions(
            self.user, 'test_mass_invalidation'
        )
        
        self.assertEqual(invalidated_count, 3)
        
        # All sessions should be invalid now
        self.assertIsNone(self.session_manager.validate_session(session1.session_id))
        self.assertIsNone(self.session_manager.validate_session(session2.session_id))
        self.assertIsNone(self.session_manager.validate_session(session3.session_id))
    
    def test_session_limit_enforcement(self):
        """Test session limit enforcement"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Set low session limit for testing
        original_limit = self.session_manager.MAX_SESSIONS_PER_USER
        self.session_manager.MAX_SESSIONS_PER_USER = 2
        
        try:
            # Create sessions up to limit
            session1 = self.session_manager.create_session(user=self.user, request=request)
            session2 = self.session_manager.create_session(user=self.user, request=request)
            
            # Both should be active
            self.assertTrue(SecureUserSession.objects.get(session_id=session1.session_id).is_active)
            self.assertTrue(SecureUserSession.objects.get(session_id=session2.session_id).is_active)
            
            # Create one more session (should trigger limit enforcement)
            session3 = self.session_manager.create_session(user=self.user, request=request)
            
            # Newest session should be active
            self.assertTrue(SecureUserSession.objects.get(session_id=session3.session_id).is_active)
            
            # Check that oldest session was deactivated
            active_sessions = SecureUserSession.get_user_active_sessions(self.user)
            self.assertEqual(active_sessions.count(), 2)
            
        finally:
            # Restore original limit
            self.session_manager.MAX_SESSIONS_PER_USER = original_limit
    
    def test_get_user_sessions(self):
        """Test getting user sessions"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Create sessions
        session1 = self.session_manager.create_session(user=self.user, request=request)
        session2 = self.session_manager.create_session(user=self.user, request=request)
        
        # Get user sessions
        sessions = self.session_manager.get_user_sessions(self.user)
        
        self.assertEqual(len(sessions), 2)
        
        # Check session data structure
        for session_info in sessions:
            self.assertIn('session_id', session_info)
            self.assertIn('created_at', session_info)
            self.assertIn('last_activity', session_info)
            self.assertIn('ip_address', session_info)
            self.assertIn('device_type', session_info)
            # Session ID should be truncated for security
            self.assertTrue(session_info['session_id'].endswith('...'))
    
    def test_session_cleanup(self):
        """Test expired session cleanup"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Create session and manually expire it
        session = self.session_manager.create_session(user=self.user, request=request)
        
        # Manually set expiration to past
        session.expires_at = timezone.now() - timedelta(hours=1)
        session.save()
        
        # Run cleanup
        cleanup_count = self.session_manager.cleanup_expired_sessions()
        
        self.assertEqual(cleanup_count, 1)
        
        # Check session is marked inactive
        session.refresh_from_db()
        self.assertFalse(session.is_active)
    
    def test_session_statistics(self):
        """Test session statistics"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Create some sessions
        session1 = self.session_manager.create_session(user=self.user, request=request)
        session2 = self.session_manager.create_session(user=self.user, request=request)
        
        # Mark one as suspicious
        session1.mark_suspicious('test_reason')
        
        # Get statistics
        stats = self.session_manager.get_session_statistics()
        
        self.assertIn('total_active_sessions', stats)
        self.assertIn('suspicious_sessions', stats)
        self.assertIn('recent_logins', stats)
        self.assertIn('sessions_by_device', stats)
        
        self.assertEqual(stats['total_active_sessions'], 2)
        self.assertEqual(stats['suspicious_sessions'], 1)
    
    def test_client_info_extraction(self):
        """Test client information extraction"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        request.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.1, 192.168.1.1'
        
        client_info = self.session_manager._extract_client_info(request)
        
        self.assertEqual(client_info['ip_address'], '203.0.113.1')  # Should use X-Forwarded-For
        self.assertIn('user_agent', client_info)
        self.assertIn('user_agent_hash', client_info)
        self.assertIn('session_fingerprint', client_info)
        self.assertIn('device_type', client_info)
        self.assertIn('browser_name', client_info)
        self.assertIn('os_name', client_info)
        
        # Check that hashes are generated
        self.assertEqual(len(client_info['user_agent_hash']), 64)  # SHA256 hash
        self.assertEqual(len(client_info['session_fingerprint']), 64)  # SHA256 hash


class TestSecureSessionManagerIntegration(APITestCase):
    """Integration tests for SecureSessionManager with JWT authentication"""
    
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
    
    def tearDown(self):
        # Clean up
        cache.clear()
        SecureUserSession.objects.all().delete()
    
    def test_login_creates_secure_session(self):
        """Test that JWT login creates a secure session"""
        login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        response = self.client.post('/api/auth/jwt/login/', login_data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        
        # Check that secure session was created
        sessions = SecureUserSession.objects.filter(user=self.user, is_active=True)
        self.assertEqual(sessions.count(), 1)
        
        session = sessions.first()
        self.assertEqual(session.user, self.user)
        self.assertTrue(session.is_active)
        self.assertFalse(session.is_suspicious)
    
    def test_get_user_sessions_endpoint(self):
        """Test the user sessions endpoint"""
        # First login to create session and get token
        login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        login_response = self.client.post('/api/auth/jwt/login/', login_data)
        access_token = login_response.cookies['access_token'].value
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        # Get user sessions
        response = self.client.get('/api/auth/jwt/sessions/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['total_sessions'], 1)
        self.assertEqual(len(response.data['sessions']), 1)
        
        # Check session data structure
        session_data = response.data['sessions'][0]
        self.assertIn('session_id', session_data)
        self.assertIn('created_at', session_data)
        self.assertIn('ip_address', session_data)
        self.assertIn('device_type', session_data)
    
    def test_session_statistics_endpoint_admin_only(self):
        """Test that session statistics endpoint requires admin access"""
        # First login as regular user
        login_data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        login_response = self.client.post('/api/auth/jwt/login/', login_data)
        access_token = login_response.cookies['access_token'].value
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        # Try to get statistics (should fail)
        response = self.client.get('/api/auth/jwt/sessions/statistics/')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error']['code'], 'PERMISSION_DENIED')
        
        # Make user admin and try again
        self.user.is_superuser = True
        self.user.save()
        
        response = self.client.get('/api/auth/jwt/sessions/statistics/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIn('statistics', response.data)


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