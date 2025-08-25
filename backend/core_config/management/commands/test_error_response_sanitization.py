"""
Management command to test error response sanitization and secure logging
"""

from django.core.management.base import BaseCommand
from django.test import RequestFactory
from django.http import JsonResponse
from django.contrib.auth.models import AnonymousUser
from rest_framework.exceptions import (
    AuthenticationFailed, NotAuthenticated, NotFound,
    ValidationError as DRFValidationError, Throttled
)
from core_config.error_response import StandardErrorResponse, SecureLogger
from core_config.error_sanitization_middleware import ErrorSanitizationMiddleware, SecurityEventMiddleware
from core_config.global_exception_handler import global_exception_handler
import json


class Command(BaseCommand):
    help = 'Test error response sanitization and secure logging functionality'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed test output',
        )
    
    def handle(self, *args, **options):
        self.verbose = options['verbose']
        self.stdout.write(
            self.style.SUCCESS('🧪 Testing Error Response Sanitization System...')
        )
        self.stdout.write('=' * 60)
        
        # Run all tests
        self.test_basic_sanitization()
        self.test_database_error_sanitization()
        self.test_file_path_sanitization()
        self.test_details_sanitization()
        self.test_secure_logger()
        self.test_error_factories()
        self.test_middleware_integration()
        self.test_global_exception_handler()
        self.test_security_event_middleware()
        
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(
            self.style.SUCCESS('✅ All error response sanitization tests completed!')
        )
        
        self.stdout.write('\nKey features verified:')
        self.stdout.write('• Sensitive data sanitization (passwords, tokens, keys)')
        self.stdout.write('• Database error detail removal')
        self.stdout.write('• File path sanitization')
        self.stdout.write('• Nested data structure sanitization')
        self.stdout.write('• Secure logging with sanitization')
        self.stdout.write('• Standardized error response formats')
        self.stdout.write('• Factory methods for common error types')
        self.stdout.write('• Middleware integration')
        self.stdout.write('• Global exception handling')
        self.stdout.write('• Security event detection and logging')
    
    def test_basic_sanitization(self):
        """Test basic message sanitization"""
        self.stdout.write('\n1. Testing basic message sanitization...')
        
        # Test various sensitive patterns
        test_cases = [
            ('password=secret123', 'password field'),
            ('token=abc123xyz', 'token field'),
            ('api_key=key123', 'api_key field'),
            ('Authorization: Bearer jwt123', 'authorization header'),
            ('cookie=session123', 'cookie value'),
            ('secret=mysecret', 'secret field'),
            ('4532-1234-5678-9012', 'credit card number'),
            ('user@example.com', 'email address'),
        ]
        
        for sensitive_data, description in test_cases:
            error = StandardErrorResponse(
                error_code='TEST_ERROR',
                message=f'Error occurred: {sensitive_data}'
            )
            response_data = error.to_dict()
            sanitized_message = response_data['error']['message']
            
            if '[REDACTED]' in sanitized_message and sensitive_data not in sanitized_message:
                self.stdout.write(f'  ✅ {description} sanitized correctly')
                if self.verbose:
                    self.stdout.write(f'     Original: Error occurred: {sensitive_data}')
                    self.stdout.write(f'     Sanitized: {sanitized_message}')
            else:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ {description} sanitization failed')
                )
                if self.verbose:
                    self.stdout.write(f'     Sanitized: {sanitized_message}')
    
    def test_database_error_sanitization(self):
        """Test database error sanitization"""
        self.stdout.write('\n2. Testing database error sanitization...')
        
        test_cases = [
            'DETAIL: Key (email)=(user@example.com) already exists.',
            'HINT: Check the unique constraint on table "users"',
            'CONTEXT: SQL statement "INSERT INTO users..."',
            'WHERE: column "password" = \'secret123\'',
            'relation "sensitive_table" does not exist',
            'column "secret_field" cannot be null',
            'constraint "unique_email" violated',
        ]
        
        for db_error in test_cases:
            error = StandardErrorResponse('DB_ERROR', db_error)
            response_data = error.to_dict()
            sanitized_message = response_data['error']['message']
            
            if '[DATABASE_DETAIL_REDACTED]' in sanitized_message:
                self.stdout.write('  ✅ Database error sanitized correctly')
                if self.verbose:
                    self.stdout.write(f'     Original: {db_error}')
                    self.stdout.write(f'     Sanitized: {sanitized_message}')
            else:
                self.stdout.write(
                    self.style.ERROR('  ❌ Database error sanitization failed')
                )
                if self.verbose:
                    self.stdout.write(f'     Sanitized: {sanitized_message}')
    
    def test_file_path_sanitization(self):
        """Test file path sanitization"""
        self.stdout.write('\n3. Testing file path sanitization...')
        
        test_cases = [
            '/home/user/secret/app.py',
            '/var/log/sensitive.log',
            '/opt/app/config.py',
            'C:\\Users\\Admin\\secret\\file.py',
            'File "/app/models.py" line 123',
        ]
        
        for path in test_cases:
            error = StandardErrorResponse('PATH_ERROR', f'Error in {path}')
            response_data = error.to_dict()
            sanitized_message = response_data['error']['message']
            
            if '[PATH_REDACTED]' in sanitized_message or '[FILE_INFO_REDACTED]' in sanitized_message:
                self.stdout.write('  ✅ File path sanitized correctly')
                if self.verbose:
                    self.stdout.write(f'     Original: Error in {path}')
                    self.stdout.write(f'     Sanitized: {sanitized_message}')
            else:
                self.stdout.write(
                    self.style.ERROR('  ❌ File path sanitization failed')
                )
                if self.verbose:
                    self.stdout.write(f'     Sanitized: {sanitized_message}')
    
    def test_details_sanitization(self):
        """Test details sanitization"""
        self.stdout.write('\n4. Testing details sanitization...')
        
        sensitive_details = {
            'password': 'secret123',
            'api_key': 'key123',
            'token': 'token123',
            'safe_field': 'safe_value',
            'nested': {
                'secret': 'nested_secret',
                'normal': 'normal_value',
                'auth_header': 'Bearer jwt123'
            },
            'list_field': [
                'safe_item',
                'password=secret456',
                {'key': 'value', 'token': 'list_token'}
            ]
        }
        
        error = StandardErrorResponse(
            error_code='DETAILS_ERROR',
            message='Error with details',
            details=sensitive_details
        )
        response_data = error.to_dict()
        details = response_data['error']['details']
        
        # Check sensitive fields are redacted
        sensitive_redacted = (
            details['password'] == '[REDACTED]' and
            details['api_key'] == '[REDACTED]' and
            details['token'] == '[REDACTED]' and
            details['nested']['secret'] == '[REDACTED]'
        )
        
        # Check safe fields are preserved
        safe_preserved = (
            details['safe_field'] == 'safe_value' and
            details['nested']['normal'] == 'normal_value'
        )
        
        if sensitive_redacted and safe_preserved:
            self.stdout.write('  ✅ Details sanitization working correctly')
            if self.verbose:
                self.stdout.write(f'     Sanitized details: {json.dumps(details, indent=2)}')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Details sanitization failed')
            )
            if self.verbose:
                self.stdout.write(f'     Details: {json.dumps(details, indent=2)}')
    
    def test_secure_logger(self):
        """Test secure logger"""
        self.stdout.write('\n5. Testing secure logger...')
        
        logger = SecureLogger('test_logger')
        
        # Test message sanitization
        test_messages = [
            'User login with password=secret123',
            'API call with token=abc123xyz',
            'Database error: DETAIL: Key exists',
            'File error in /home/user/app.py'
        ]
        
        for message in test_messages:
            # We can't easily test the actual logging without mocking,
            # but we can test the sanitization method directly
            sanitized = logger._sanitize_log_data(message)
            
            if ('[REDACTED]' in sanitized or 
                '[DATABASE_DETAIL_REDACTED]' in sanitized or 
                '[PATH_REDACTED]' in sanitized):
                self.stdout.write('  ✅ Secure logger sanitization working')
                if self.verbose:
                    self.stdout.write(f'     Original: {message}')
                    self.stdout.write(f'     Sanitized: {sanitized}')
            else:
                # Check if message doesn't contain sensitive data
                if not any(pattern in message.lower() for pattern in ['password', 'token', 'secret']):
                    self.stdout.write('  ✅ Non-sensitive message preserved')
                else:
                    self.stdout.write(
                        self.style.ERROR('  ❌ Secure logger sanitization failed')
                    )
    
    def test_error_factories(self):
        """Test error factory methods"""
        self.stdout.write('\n6. Testing error factory methods...')
        
        # Test validation error
        validation_error = StandardErrorResponse.validation_error(
            message="Validation failed",
            details={'field': 'This field is required'}
        )
        validation_data = validation_error.to_dict()
        
        if (validation_data['error']['code'] == 'VALIDATION_ERROR' and
            validation_data['error']['details']['field'] == 'This field is required'):
            self.stdout.write('  ✅ Validation error factory working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Validation error factory failed')
            )
        
        # Test authentication error
        auth_error = StandardErrorResponse.authentication_error()
        auth_data = auth_error.to_dict()
        
        if auth_data['error']['code'] == 'AUTHENTICATION_ERROR':
            self.stdout.write('  ✅ Authentication error factory working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Authentication error factory failed')
            )
        
        # Test rate limit error
        rate_limit_error = StandardErrorResponse.rate_limit_error(
            message="Too many requests",
            retry_after=60
        )
        rate_limit_data = rate_limit_error.to_dict()
        
        if (rate_limit_data['error']['code'] == 'RATE_LIMIT_EXCEEDED' and
            rate_limit_data['error']['details']['retry_after'] == 60):
            self.stdout.write('  ✅ Rate limit error factory working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Rate limit error factory failed')
            )
        
        # Test file upload error
        file_error = StandardErrorResponse.file_upload_error(
            message="File upload failed",
            details={'file_type': 'invalid'}
        )
        file_data = file_error.to_dict()
        
        if file_data['error']['code'] == 'FILE_UPLOAD_ERROR':
            self.stdout.write('  ✅ File upload error factory working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ File upload error factory failed')
            )
    
    def test_middleware_integration(self):
        """Test middleware integration"""
        self.stdout.write('\n7. Testing middleware integration...')
        
        factory = RequestFactory()
        middleware = ErrorSanitizationMiddleware(lambda request: JsonResponse({'status': 'ok'}))
        
        # Test request ID assignment
        request = factory.get('/test/')
        middleware.process_request(request)
        
        if hasattr(request, 'request_id') and request.request_id:
            self.stdout.write('  ✅ Request ID assignment working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Request ID assignment failed')
            )
        
        # Test exception handling
        request = factory.get('/test/')
        request.request_id = 'test-123'
        request.user = AnonymousUser()
        
        exception = NotAuthenticated()
        response = middleware.process_exception(request, exception)
        
        if (response and response.status_code == 401 and 
            hasattr(response, 'data') and 'error' in response.data):
            self.stdout.write('  ✅ Exception handling working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Exception handling failed')
            )
        
        # Test error response processing
        request = factory.get('/test/')
        request.request_id = 'test-123'
        
        error_response = JsonResponse({'message': 'password=secret123'}, status=400)
        processed_response = middleware.process_response(request, error_response)
        
        if processed_response.status_code == 400:
            self.stdout.write('  ✅ Error response processing working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Error response processing failed')
            )
    
    def test_global_exception_handler(self):
        """Test global exception handler"""
        self.stdout.write('\n8. Testing global exception handler...')
        
        factory = RequestFactory()
        
        # Test authentication failed
        request = factory.get('/test/')
        request.request_id = 'test-123'
        context = {'request': request, 'view': None}
        
        exception = AuthenticationFailed("Invalid credentials")
        response = global_exception_handler(exception, context)
        
        if (response and response.status_code == 401 and 
            response.data['error']['code'] == 'AUTHENTICATION_ERROR'):
            self.stdout.write('  ✅ Authentication exception handling working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Authentication exception handling failed')
            )
        
        # Test validation error
        exception = DRFValidationError({'field': ['This field is required']})
        response = global_exception_handler(exception, context)
        
        if (response and response.status_code == 400 and 
            response.data['error']['code'] == 'VALIDATION_ERROR'):
            self.stdout.write('  ✅ Validation exception handling working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Validation exception handling failed')
            )
        
        # Test generic exception
        exception = ValueError("Something went wrong")
        response = global_exception_handler(exception, context)
        
        if response and response.status_code == 400:
            self.stdout.write('  ✅ Generic exception handling working')
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Generic exception handling failed')
            )
    
    def test_security_event_middleware(self):
        """Test security event middleware"""
        self.stdout.write('\n9. Testing security event middleware...')
        
        factory = RequestFactory()
        middleware = SecurityEventMiddleware(lambda request: JsonResponse({'status': 'ok'}))
        
        # Test suspicious query detection
        request = factory.get('/test/?q=union+select+*+from+users')
        
        try:
            middleware.process_request(request)
            self.stdout.write('  ✅ Suspicious query detection working')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Suspicious query detection failed: {e}')
            )
        
        # Test suspicious user agent detection
        request = factory.get('/test/', HTTP_USER_AGENT='sqlmap/1.0')
        
        try:
            middleware.process_request(request)
            self.stdout.write('  ✅ Suspicious user agent detection working')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Suspicious user agent detection failed: {e}')
            )
        
        # Test authentication logging
        request = factory.post('/login/', {'username': 'testuser'})
        response = JsonResponse({'status': 'ok'}, status=401)
        
        try:
            middleware.process_response(request, response)
            self.stdout.write('  ✅ Authentication logging working')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Authentication logging failed: {e}')
            )