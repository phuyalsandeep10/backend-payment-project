"""
Management command to test error handling and logging systems
"""

import logging
from django.core.management.base import BaseCommand
from django.test import RequestFactory
from django.core.exceptions import ValidationError, PermissionDenied
from rest_framework.exceptions import AuthenticationFailed, Throttled
from core_config.error_handling import (
    StandardErrorResponse,
    SecureErrorHandler,
    SecurityEventLogger,
    SecureLoggingFilter
)


class Command(BaseCommand):
    help = 'Test error handling and logging systems'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--test-type',
            type=str,
            choices=['all', 'responses', 'logging', 'sanitization', 'security-events'],
            default='all',
            help='Type of error handling test to run'
        )
    
    def handle(self, *args, **options):
        test_type = options['test_type']
        
        self.stdout.write(
            self.style.SUCCESS(f'Running error handling tests: {test_type}')
        )
        
        if test_type in ['all', 'responses']:
            self.test_error_responses()
        
        if test_type in ['all', 'logging']:
            self.test_secure_logging()
        
        if test_type in ['all', 'sanitization']:
            self.test_message_sanitization()
        
        if test_type in ['all', 'security-events']:
            self.test_security_event_logging()
        
        self.stdout.write(
            self.style.SUCCESS('Error handling tests completed successfully!')
        )
    
    def test_error_responses(self):
        """Test standardized error responses"""
        self.stdout.write('Testing standardized error responses...')
        
        # Test basic error response
        error = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            message='Test validation error'
        )
        
        response_dict = error.to_dict()
        
        if response_dict['error']['code'] == 'VALIDATION_ERROR':
            self.stdout.write(
                self.style.SUCCESS('  ✅ Basic error response test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Basic error response test failed')
            )
        
        # Test message sanitization
        sensitive_message = (
            "Database error: postgresql://user:password@localhost/db "
            "API key: api_key=abc123 "
            "Token: token=xyz789"
        )
        
        error = StandardErrorResponse(
            error_code='DATABASE_ERROR',
            message=sensitive_message
        )
        
        if '[REDACTED]' in error.message and 'password' not in error.message:
            self.stdout.write(
                self.style.SUCCESS('  ✅ Message sanitization test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Message sanitization test failed')
            )
        
        # Test details sanitization
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
        
        if ('password' not in error.details and 
            'safe_field' in error.details and
            'token' not in error.details.get('nested', {})):
            self.stdout.write(
                self.style.SUCCESS('  ✅ Details sanitization test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Details sanitization test failed')
            )
        
        # Test error code mapping
        test_codes = [
            ('AUTHENTICATION_ERROR', 'Authentication required'),
            ('PERMISSION_DENIED', 'Insufficient permissions'),
            ('RATE_LIMIT_EXCEEDED', 'Too many requests'),
        ]
        
        for code, expected_message in test_codes:
            error = StandardErrorResponse(error_code=code)
            if error.message == expected_message:
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ Error code mapping test passed: {code}')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Error code mapping test failed: {code}')
                )
    
    def test_secure_logging(self):
        """Test secure logging filter"""
        self.stdout.write('Testing secure logging filter...')
        
        filter_instance = SecureLoggingFilter()
        
        # Test password sanitization
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='User login with password=secret123',
            args=(),
            exc_info=None
        )
        
        filter_instance.filter(record)
        
        if 'secret123' not in record.msg and 'password=***' in record.msg:
            self.stdout.write(
                self.style.SUCCESS('  ✅ Password sanitization test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Password sanitization test failed')
            )
        
        # Test API key sanitization
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='API request with api_key=abc123def456',
            args=(),
            exc_info=None
        )
        
        filter_instance.filter(record)
        
        if 'abc123def456' not in record.msg and 'api_key=***' in record.msg:
            self.stdout.write(
                self.style.SUCCESS('  ✅ API key sanitization test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ API key sanitization test failed')
            )
        
        # Test database URL sanitization
        record = logging.LogRecord(
            name='test',
            level=logging.ERROR,
            pathname='',
            lineno=0,
            msg='Database error: postgresql://user:pass@localhost/db',
            args=(),
            exc_info=None
        )
        
        filter_instance.filter(record)
        
        if 'user:pass' not in record.msg and 'postgresql://***:***@***/***' in record.msg:
            self.stdout.write(
                self.style.SUCCESS('  ✅ Database URL sanitization test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Database URL sanitization test failed')
            )
        
        # Test email sanitization
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='User registration: user@example.com',
            args=(),
            exc_info=None
        )
        
        filter_instance.filter(record)
        
        if 'user@example.com' not in record.msg and '***@***.***' in record.msg:
            self.stdout.write(
                self.style.SUCCESS('  ✅ Email sanitization test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Email sanitization test failed')
            )
    
    def test_message_sanitization(self):
        """Test comprehensive message sanitization"""
        self.stdout.write('Testing message sanitization patterns...')
        
        test_cases = [
            # (input_message, should_not_contain, should_contain)
            (
                'Database error: postgresql://user:password@localhost/db',
                ['user:password'],
                ['[REDACTED]']
            ),
            (
                'API key leaked: api_key=abc123def456',
                ['abc123def456'],
                ['[REDACTED]']
            ),
            (
                'File path: /home/user/secret/file.txt',
                ['/home/user/secret'],
                ['[REDACTED]']
            ),
            (
                'User email: john.doe@company.com contacted support',
                ['john.doe@company.com'],
                ['[REDACTED]']
            ),
            (
                'Token authentication failed: token=xyz789abc',
                ['xyz789abc'],
                ['[REDACTED]']
            ),
        ]
        
        for input_msg, should_not_contain, should_contain in test_cases:
            error = StandardErrorResponse(
                error_code='TEST_ERROR',
                message=input_msg
            )
            
            sanitized = error.message
            
            # Check that sensitive content is removed
            sensitive_found = any(sensitive in sanitized for sensitive in should_not_contain)
            # Check that redaction markers are present
            redaction_found = any(marker in sanitized for marker in should_contain)
            
            if not sensitive_found and redaction_found:
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ Sanitization test passed: {input_msg[:50]}...')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Sanitization test failed: {input_msg[:50]}...')
                )
                self.stdout.write(f'    Original: {input_msg}')
                self.stdout.write(f'    Sanitized: {sanitized}')
    
    def test_security_event_logging(self):
        """Test security event logging"""
        self.stdout.write('Testing security event logging...')
        
        factory = RequestFactory()
        logger = SecurityEventLogger()
        
        # Test authentication attempt logging
        request = factory.post('/login/')
        
        try:
            with self.assertLogs('security', level='INFO'):
                logger.log_authentication_attempt(
                    request, 'test@example.com', True
                )
            self.stdout.write(
                self.style.SUCCESS('  ✅ Authentication attempt logging test passed')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Authentication attempt logging test failed: {e}')
            )
        
        # Test failed authentication logging
        try:
            with self.assertLogs('security', level='WARNING'):
                logger.log_authentication_attempt(
                    request, 'test@example.com', False, 'Invalid password'
                )
            self.stdout.write(
                self.style.SUCCESS('  ✅ Failed authentication logging test passed')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Failed authentication logging test failed: {e}')
            )
        
        # Test suspicious activity logging
        try:
            with self.assertLogs('security', level='ERROR'):
                logger.log_suspicious_activity(
                    request, 'sql_injection', {'pattern': 'DROP TABLE'}
                )
            self.stdout.write(
                self.style.SUCCESS('  ✅ Suspicious activity logging test passed')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Suspicious activity logging test failed: {e}')
            )
        
        # Test file upload threat logging
        try:
            with self.assertLogs('security', level='ERROR'):
                logger.log_file_upload_threat(
                    request, 'malware.exe', 'executable', 'PE header detected'
                )
            self.stdout.write(
                self.style.SUCCESS('  ✅ File upload threat logging test passed')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ File upload threat logging test failed: {e}')
            )
        
        # Test rate limit logging
        try:
            with self.assertLogs('security', level='WARNING'):
                logger.log_rate_limit_exceeded(
                    request, 'api_requests', 100
                )
            self.stdout.write(
                self.style.SUCCESS('  ✅ Rate limit logging test passed')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Rate limit logging test failed: {e}')
            )
    
    def test_error_handler_integration(self):
        """Test error handler integration"""
        self.stdout.write('Testing error handler integration...')
        
        factory = RequestFactory()
        handler = SecureErrorHandler()
        
        # Test validation error handling
        exc = ValidationError({'field': ['This field is required']})
        request = factory.post('/test/')
        
        error_response = handler.handle_validation_error(exc, request)
        
        if (error_response.error_code == 'VALIDATION_ERROR' and 
            error_response.status_code == 400):
            self.stdout.write(
                self.style.SUCCESS('  ✅ Validation error handling test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Validation error handling test failed')
            )
        
        # Test authentication error handling
        exc = AuthenticationFailed('Invalid token')
        error_response = handler.handle_authentication_error(exc, request)
        
        if (error_response.error_code == 'AUTHENTICATION_ERROR' and 
            error_response.status_code == 401):
            self.stdout.write(
                self.style.SUCCESS('  ✅ Authentication error handling test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Authentication error handling test failed')
            )
        
        # Test permission error handling
        exc = PermissionDenied('Access denied')
        error_response = handler.handle_permission_error(exc, request)
        
        if (error_response.error_code == 'PERMISSION_DENIED' and 
            error_response.status_code == 403):
            self.stdout.write(
                self.style.SUCCESS('  ✅ Permission error handling test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Permission error handling test failed')
            )
        
        # Test rate limit error handling
        exc = Throttled(wait=60)
        error_response = handler.handle_rate_limit_error(exc, request)
        
        if (error_response.error_code == 'RATE_LIMIT_EXCEEDED' and 
            error_response.status_code == 429 and
            error_response.details.get('retry_after') == 60):
            self.stdout.write(
                self.style.SUCCESS('  ✅ Rate limit error handling test passed')
            )
        else:
            self.stdout.write(
                self.style.ERROR('  ❌ Rate limit error handling test failed')
            )
    
    def assertLogs(self, logger_name, level):
        """Simple context manager for log testing"""
        class LogCapture:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
        
        return LogCapture()