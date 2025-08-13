"""
Test cases for the comprehensive input validation service
"""

import pytest
from django.test import TestCase, RequestFactory
from django.core.exceptions import ValidationError
from core_config.security import InputValidationService, CSRFProtectionService
from core_config.validation_schemas import ValidationSchemas
from core_config.validation_middleware import InputValidationMiddleware


class TestInputValidationService(TestCase):
    """Test cases for InputValidationService"""
    
    def setUp(self):
        self.validator = InputValidationService()
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1 UNION SELECT * FROM users",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --"
        ]
        
        for malicious_input in malicious_inputs:
            with self.assertRaises(ValidationError):
                self.validator.validate_and_sanitize({'test_field': malicious_input})
    
    def test_xss_detection(self):
        """Test XSS pattern detection"""
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "onload=alert('xss')",
            "<object data='data:text/html,<script>alert(1)</script>'></object>"
        ]
        
        for malicious_input in malicious_inputs:
            with self.assertRaises(ValidationError):
                self.validator.validate_and_sanitize({'test_field': malicious_input})
    
    def test_path_traversal_detection(self):
        """Test path traversal pattern detection"""
        malicious_inputs = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        for malicious_input in malicious_inputs:
            with self.assertRaises(ValidationError):
                self.validator.validate_and_sanitize({'test_field': malicious_input})
    
    def test_command_injection_detection(self):
        """Test command injection pattern detection"""
        malicious_inputs = [
            "; cat /etc/passwd",
            "| whoami",
            "&& rm -rf /",
            "`id`",
            "$(whoami)",
            "; ping google.com"
        ]
        
        for malicious_input in malicious_inputs:
            with self.assertRaises(ValidationError):
                self.validator.validate_and_sanitize({'test_field': malicious_input})
    
    def test_valid_input_sanitization(self):
        """Test that valid inputs are properly sanitized"""
        test_data = {
            'name': '  John Doe  ',
            'email': 'JOHN.DOE@EXAMPLE.COM',
            'description': '<p>This is a <strong>valid</strong> description</p>'
        }
        
        schema = {
            'name': {'type': 'string', 'max_length': 100},
            'email': {'type': 'email'},
            'description': {'type': 'string', 'allow_html': True, 'max_length': 500}
        }
        
        result = self.validator.validate_and_sanitize(test_data, schema)
        
        # Check sanitization
        self.assertEqual(result['name'], 'John Doe')  # Trimmed
        self.assertEqual(result['email'], 'john.doe@example.com')  # Lowercased
        self.assertIn('<p>', result['description'])  # HTML preserved
        self.assertIn('<strong>', result['description'])
    
    def test_html_sanitization(self):
        """Test HTML sanitization for fields that don't allow HTML"""
        test_data = {
            'comment': '<script>alert("xss")</script><p>Valid content</p>'
        }
        
        schema = {
            'comment': {'type': 'string', 'allow_html': False, 'max_length': 500}
        }
        
        result = self.validator.validate_and_sanitize(test_data, schema)
        
        # HTML should be stripped and escaped
        self.assertNotIn('<script>', result['comment'])
        self.assertNotIn('<p>', result['comment'])
        self.assertIn('Valid content', result['comment'])
    
    def test_email_validation(self):
        """Test email field validation"""
        # Valid emails
        valid_emails = [
            'user@example.com',
            'test.email+tag@domain.co.uk',
            'user123@test-domain.com'
        ]
        
        for email in valid_emails:
            result = self.validator.validate_email_field(email)
            self.assertEqual(result, email.lower())
        
        # Invalid emails
        invalid_emails = [
            'invalid-email',
            '@domain.com',
            'user@',
            'user..double.dot@domain.com',
            'user@domain',
            '<script>alert("xss")</script>@domain.com'
        ]
        
        for email in invalid_emails:
            with self.assertRaises(ValidationError):
                self.validator.validate_email_field(email)
    
    def test_financial_field_validation(self):
        """Test financial amount validation"""
        # Valid amounts
        valid_amounts = ['100.50', '1000', '0.01', '999999.9999']
        
        for amount in valid_amounts:
            result = self.validator.validate_financial_field(amount)
            self.assertEqual(result, amount)
        
        # Invalid amounts
        invalid_amounts = [
            '-100',  # Negative
            '100.123456',  # Too many decimals
            'abc',  # Non-numeric
            '100; DROP TABLE payments;',  # SQL injection
            '$(rm -rf /)',  # Command injection
        ]
        
        for amount in invalid_amounts:
            with self.assertRaises(ValidationError):
                self.validator.validate_financial_field(amount)
    
    def test_nested_data_validation(self):
        """Test validation of nested data structures"""
        test_data = {
            'user': {
                'name': 'John Doe',
                'email': 'john@example.com'
            },
            'items': [
                {'name': 'Item 1', 'price': '10.50'},
                {'name': 'Item 2', 'price': '20.00'}
            ]
        }
        
        schema = {
            'user': {'type': 'dict'},
            'items': {'type': 'list'}
        }
        
        # Should not raise exception for valid nested data
        result = self.validator.validate_and_sanitize(test_data, schema)
        self.assertIsInstance(result['user'], dict)
        self.assertIsInstance(result['items'], list)


class TestValidationSchemas(TestCase):
    """Test cases for ValidationSchemas"""
    
    def test_get_schema_by_name(self):
        """Test getting schema by name"""
        schema = ValidationSchemas.get_schema('LOGIN_SCHEMA')
        self.assertIn('email', schema)
        self.assertIn('password', schema)
    
    def test_get_endpoint_schema(self):
        """Test getting schema for specific endpoint"""
        schema = ValidationSchemas.get_endpoint_schema('auth/login', 'POST')
        self.assertIn('email', schema)
        self.assertIn('password', schema)
        
        # Test non-existent endpoint
        schema = ValidationSchemas.get_endpoint_schema('non/existent', 'POST')
        self.assertEqual(schema, {})


class TestInputValidationMiddleware(TestCase):
    """Test cases for InputValidationMiddleware"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = InputValidationMiddleware(lambda request: None)
    
    def test_skip_validation_for_safe_methods(self):
        """Test that GET requests skip validation"""
        request = self.factory.get('/api/users/')
        response = self.middleware.process_request(request)
        self.assertIsNone(response)  # Should not block request
    
    def test_skip_validation_for_excluded_endpoints(self):
        """Test that excluded endpoints skip validation"""
        request = self.factory.post('/api/admin/login/')
        response = self.middleware.process_request(request)
        self.assertIsNone(response)  # Should not block request
    
    def test_validation_for_api_endpoints(self):
        """Test that API endpoints are validated"""
        # This would require more complex setup with actual request data
        # For now, just test that the middleware is properly configured
        self.assertTrue(hasattr(self.middleware, 'process_request'))
        self.assertTrue(hasattr(self.middleware, '_get_request_data'))
        self.assertTrue(hasattr(self.middleware, '_get_validation_schema'))


class TestCSRFProtectionService(TestCase):
    """Test cases for CSRFProtectionService"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.csrf_service = CSRFProtectionService()
    
    def test_csrf_token_generation(self):
        """Test CSRF token generation"""
        request = self.factory.get('/')
        token = self.csrf_service.get_csrf_token(request)
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 10)  # Should be a reasonable length


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
                'core_config',
            ],
            SECRET_KEY='test-secret-key',
            USE_TZ=True,
        )
    
    django.setup()
    
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(['__main__'])
    
    if failures:
        exit(1)