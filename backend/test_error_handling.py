"""
Comprehensive test suite for secure error handling and logging
"""

import logging
import json
from django.test import TestCase, RequestFactory
from django.core.exceptions import ValidationError, PermissionDenied
from django.contrib.auth.models import AnonymousUser
from rest_framework.exceptions import AuthenticationFailed, Throttled
from rest_framework.test import APITestCase
from core_config.error_handling import (
    StandardErrorResponse, 
    SecureErrorHandler, 
    custom_exception_handler,
    SecureLoggingFilter,
    SecurityEventLogger
)
from authentication.models import User


class TestStandardErrorResponse(TestCase):
    """Test cases for StandardErrorResponse"""
    
    def test_basic_error_response(self):
        """Test basic error response creation"""
        error = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            message='Test error message'
        )
        
        response_dict = error.to_dict()
        
        self.assertEqual(response_dict['error']['code'], 'VALIDATION_ERROR')
        self.assertEqual(response_dict['error']['message'], 'Test error message')
        self.assertIn('correlation_id', response_dict['error'])
    
    def test_message_sanitization(self):
        """Test that sensitive information is removed from error messages"""
        sensitive_message = (
            "Database error: postgresql://user:password@localhost/db "
            "API key: api_key=abc123 "
            "File path: /home/user/secret.txt "
            "Email: user@example.com"
        )
        
        error = StandardErrorResponse(
            error_code='DATABASE_ERROR',
            message=sensitive_message
        )
        
        sanitized_message = error.message
        
        # Check that sensitive information is redacted
        self.assertNotIn('password', sanitized_message)
        self.assertNotIn('abc123', sanitized_message)
        self.assertNotIn('/home/user', sanitized_message)
        self.assertNotIn('user@example.com', sanitized_message)
        self.assertIn('[REDACTED]', sanitized_message)
    
    def test_details_sanitization(self):
        """Test that sensitive details are sanitized"""
        sensitive_details = {
            'password': 'secret123',
            'api_key': 'key123',
            'safe_field': 'safe_value',
            'nested': {
                'token': 'token123',
                'public_info': 'public'
            }
        }
        
        error = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            details=sensitive_details
        )
        
        sanitized_details = error.details
        
        # Sensitive fields should be removed
        self.assertNotIn('password', sanitized_details)
        self.assertNotIn('api_key', sanitized_details)
        
        # Safe fields should remain
        self.assertIn('safe_field', sanitized_details)
        self.assertEqual(sanitized_details['safe_field'], 'safe_value')
        
        # Nested sensitive fields should be removed
        self.assertNotIn('token', sanitized_details['nested'])
        self.assertIn('public_info', sanitized_details['nested'])
    
    def test_error_codes(self):
        """Test that error codes map to appropriate messages"""
        error = StandardErrorResponse(error_code='AUTHENTICATION_ERROR')
        self.assertEqual(error.message, 'Authentication required')
        
        error = StandardErrorResponse(error_code='PERMISSION_DENIED')
        self.assertEqual(error.message, 'Insufficient permissions')
        
        error = StandardErrorResponse(error_code='UNKNOWN_ERROR')
        self.assertEqual(error.message, 'An error occurred')
    
    def test_json_response(self):
        """Test JSON response generation"""
        error = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            message='Test message',
            status_code=400
        )
        
        response = error.to_response()
        
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        content = json.loads(response.content.decode('utf-8'))
        self.assertEqual(content['error']['code'], 'VALIDATION_ERROR')
        self.assertEqual(content['error']['message'], 'Test message')


class TestSecureErrorHandler(TestCase):
    """Test cases for SecureErrorHandler"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.handler = SecureErrorHandler()
    
    def test_validation_error_handling(self):
        """Test handling of validation errors"""
        exc = ValidationError({'field': ['This field is required']})
        request = self.factory.post('/test/')
        
        error_response = self.handler.handle_validation_error(exc, request)
        
        self.assertEqual(error_response.error_code, 'VALIDATION_ERROR')
        self.assertEqual(error_response.status_code, 400)
        self.assertIn('field', error_response.details)
    
    def test_authentication_error_handling(self):
        """Test handling of authentication errors"""
        exc = AuthenticationFailed('Invalid token')
        request = self.factory.post('/test/')
        
        error_response = self.handler.handle_authentication_error(exc, request)
        
        self.assertEqual(error_response.error_code, 'AUTHENTICATION_ERROR')
        self.assertEqual(error_response.status_code, 401)
    
    def test_permission_error_handling(self):
        """Test handling of permission errors"""
        exc = PermissionDenied('Access denied')
        request = self.factory.post('/test/')
        request.user = AnonymousUser()
        
        error_response = self.handler.handle_permission_error(exc, request)
        
        self.assertEqual(error_response.error_code, 'PERMISSION_DENIED')
        self.assertEqual(error_response.status_code, 403)
    
    def test_rate_limit_error_handling(self):
        """Test handling of rate limit errors"""
        exc = Throttled(wait=60)
        request = self.factory.post('/test/')
        
        error_response = self.handler.handle_rate_limit_error(exc, request)
        
        self.assertEqual(error_response.error_code, 'RATE_LIMIT_EXCEEDED')
        self.assertEqual(error_response.status_code, 429)
        self.assertEqual(error_response.details['retry_after'], 60)
    
    def test_generic_error_handling(self):
        """Test handling of generic errors"""
        exc = Exception('Generic error')
        request = self.factory.post('/test/')
        
        error_response = self.handler.handle_generic_error(exc, request)
        
        self.assertEqual(error_response.error_code, 'INTERNAL_ERROR')
        self.assertEqual(error_response.status_code, 500)


class TestSecureLoggingFilter(TestCase):
    """Test cases for SecureLoggingFilter"""
    
    def setUp(self):
        self.filter = SecureLoggingFilter()
    
    def test_password_sanitization(self):
        """Test that passwords are sanitized in log messages"""
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='User login with password=secret123',
            args=(),
            exc_info=None
        )
        
        self.filter.filter(record)
        
        self.assertNotIn('secret123', record.msg)
        self.assertIn('password=***', record.msg)
    
    def test_api_key_sanitization(self):
        """Test that API keys are sanitized"""
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='API request with api_key=abc123def456',
            args=(),
            exc_info=None
        )
        
        self.filter.filter(record)
        
        self.assertNotIn('abc123def456', record.msg)
        self.assertIn('api_key=***', record.msg)
    
    def test_database_url_sanitization(self):
        """Test that database URLs are sanitized"""
        record = logging.LogRecord(
            name='test',
            level=logging.ERROR,
            pathname='',
            lineno=0,
            msg='Database connection failed: postgresql://user:pass@localhost/db',
            args=(),
            exc_info=None
        )
        
        self.filter.filter(record)
        
        self.assertNotIn('user:pass', record.msg)
        self.assertIn('postgresql://***:***@***/***', record.msg)
    
    def test_email_sanitization(self):
        """Test that email addresses are sanitized"""
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='User registration: user@example.com',
            args=(),
            exc_info=None
        )
        
        self.filter.filter(record)
        
        self.assertNotIn('user@example.com', record.msg)
        self.assertIn('***@***.***', record.msg)
    
    def test_args_sanitization(self):
        """Test that log arguments are sanitized"""
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='User %s logged in with password %s',
            args=('testuser', 'secret123'),
            exc_info=None
        )
        
        self.filter.filter(record)
        
        self.assertNotIn('secret123', record.args)
        self.assertIn('***', str(record.args))


class TestSecurityEventLogger(TestCase):
    """Test cases for SecurityEventLogger"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.logger = SecurityEventLogger()
        
        # Create test user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
    
    def test_authentication_attempt_logging(self):
        """Test logging of authentication attempts"""
        request = self.factory.post('/login/')
        
        with self.assertLogs('security', level='INFO') as log:
            self.logger.log_authentication_attempt(
                request, 'test@example.com', True
            )
        
        self.assertIn('Authentication successful', log.output[0])
    
    def test_failed_authentication_logging(self):
        """Test logging of failed authentication attempts"""
        request = self.factory.post('/login/')
        
        with self.assertLogs('security', level='WARNING') as log:
            self.logger.log_authentication_attempt(
                request, 'test@example.com', False, 'Invalid password'
            )
        
        self.assertIn('Authentication failed', log.output[0])
    
    def test_permission_denied_logging(self):
        """Test logging of permission denied events"""
        request = self.factory.get('/admin/')
        
        with self.assertLogs('security', level='WARNING') as log:
            self.logger.log_permission_denied(
                request, self.user, 'admin_panel', 'view'
            )
        
        self.assertIn('Permission denied', log.output[0])
    
    def test_suspicious_activity_logging(self):
        """Test logging of suspicious activities"""
        request = self.factory.post('/api/test/')
        
        with self.assertLogs('security', level='ERROR') as log:
            self.logger.log_suspicious_activity(
                request, 'sql_injection', {'pattern': 'DROP TABLE'}
            )
        
        self.assertIn('Suspicious activity detected', log.output[0])
    
    def test_file_upload_threat_logging(self):
        """Test logging of file upload threats"""
        request = self.factory.post('/upload/')
        request.user = self.user
        
        with self.assertLogs('security', level='ERROR') as log:
            self.logger.log_file_upload_threat(
                request, 'malware.exe', 'executable', 'PE header detected'
            )
        
        self.assertIn('File upload threat detected', log.output[0])
    
    def test_rate_limit_logging(self):
        """Test logging of rate limit exceeded events"""
        request = self.factory.post('/api/test/')
        
        with self.assertLogs('security', level='WARNING') as log:
            self.logger.log_rate_limit_exceeded(
                request, 'api_requests', 100
            )
        
        self.assertIn('Rate limit exceeded', log.output[0])


class TestCustomExceptionHandler(APITestCase):
    """Integration tests for custom exception handler"""
    
    def test_validation_error_response(self):
        """Test that validation errors return standardized responses"""
        # This would require setting up a view that raises ValidationError
        # For now, we'll test the handler directly
        
        exc = ValidationError({'field': ['This field is required']})
        context = {'request': self.factory.post('/test/')}
        
        response = custom_exception_handler(exc, context)
        
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error']['code'], 'VALIDATION_ERROR')
    
    def test_authentication_error_response(self):
        """Test that authentication errors return standardized responses"""
        exc = AuthenticationFailed('Invalid token')
        context = {'request': self.factory.post('/test/')}
        
        response = custom_exception_handler(exc, context)
        
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['error']['code'], 'AUTHENTICATION_ERROR')
    
    def test_permission_error_response(self):
        """Test that permission errors return standardized responses"""
        exc = PermissionDenied('Access denied')
        context = {'request': self.factory.post('/test/')}
        
        response = custom_exception_handler(exc, context)
        
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error']['code'], 'PERMISSION_DENIED')


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
                'core_config',
            ],
            SECRET_KEY='test-secret-key',
            USE_TZ=True,
            AUTH_USER_MODEL='authentication.User',
        )
    
    django.setup()
    
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(['__main__'])
    
    if failures:
        exit(1)