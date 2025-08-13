"""
Management command to test security implementations
"""

from django.core.management.base import BaseCommand
from django.core.exceptions import ValidationError
from core_config.security import InputValidationService
from core_config.validation_schemas import ValidationSchemas


class Command(BaseCommand):
    help = 'Test security implementations'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--test-type',
            type=str,
            choices=['all', 'sql-injection', 'xss', 'path-traversal', 'validation'],
            default='all',
            help='Type of security test to run'
        )
    
    def handle(self, *args, **options):
        test_type = options['test_type']
        
        self.stdout.write(
            self.style.SUCCESS(f'Running security tests: {test_type}')
        )
        
        validator = InputValidationService()
        
        if test_type in ['all', 'sql-injection']:
            self.test_sql_injection(validator)
        
        if test_type in ['all', 'xss']:
            self.test_xss_protection(validator)
        
        if test_type in ['all', 'path-traversal']:
            self.test_path_traversal(validator)
        
        if test_type in ['all', 'validation']:
            self.test_input_validation(validator)
        
        self.stdout.write(
            self.style.SUCCESS('Security tests completed successfully!')
        )
    
    def test_sql_injection(self, validator):
        """Test SQL injection detection"""
        self.stdout.write('Testing SQL injection detection...')
        
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1 UNION SELECT * FROM users",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --"
        ]
        
        for i, malicious_input in enumerate(malicious_inputs, 1):
            try:
                validator.validate_and_sanitize({'test_field': malicious_input})
                self.stdout.write(
                    self.style.ERROR(f'  ❌ SQL injection test {i} failed: {malicious_input[:50]}...')
                )
            except ValidationError:
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ SQL injection test {i} passed')
                )
    
    def test_xss_protection(self, validator):
        """Test XSS protection"""
        self.stdout.write('Testing XSS protection...')
        
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "onload=alert('xss')"
        ]
        
        for i, malicious_input in enumerate(malicious_inputs, 1):
            try:
                validator.validate_and_sanitize({'test_field': malicious_input})
                self.stdout.write(
                    self.style.ERROR(f'  ❌ XSS test {i} failed: {malicious_input[:50]}...')
                )
            except ValidationError:
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ XSS test {i} passed')
                )
    
    def test_path_traversal(self, validator):
        """Test path traversal protection"""
        self.stdout.write('Testing path traversal protection...')
        
        malicious_inputs = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        for i, malicious_input in enumerate(malicious_inputs, 1):
            try:
                validator.validate_and_sanitize({'test_field': malicious_input})
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Path traversal test {i} failed: {malicious_input[:50]}...')
                )
            except ValidationError:
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ Path traversal test {i} passed')
                )
    
    def test_input_validation(self, validator):
        """Test input validation and sanitization"""
        self.stdout.write('Testing input validation and sanitization...')
        
        # Test valid input sanitization
        test_data = {
            'name': '  John Doe  ',
            'email': 'JOHN.DOE@EXAMPLE.COM',
            'amount': '100.50'
        }
        
        schema = {
            'name': {'type': 'string', 'max_length': 100},
            'email': {'type': 'email'},
            'amount': {'type': 'decimal', 'max_value': 1000}
        }
        
        try:
            result = validator.validate_and_sanitize(test_data, schema)
            
            # Check sanitization
            if result['name'] == 'John Doe':  # Trimmed
                self.stdout.write(self.style.SUCCESS('  ✅ Name trimming passed'))
            else:
                self.stdout.write(self.style.ERROR('  ❌ Name trimming failed'))
            
            if result['email'] == 'john.doe@example.com':  # Lowercased
                self.stdout.write(self.style.SUCCESS('  ✅ Email normalization passed'))
            else:
                self.stdout.write(self.style.ERROR('  ❌ Email normalization failed'))
            
            if result['amount'] == '100.50':
                self.stdout.write(self.style.SUCCESS('  ✅ Amount validation passed'))
            else:
                self.stdout.write(self.style.ERROR('  ❌ Amount validation failed'))
        
        except ValidationError as e:
            self.stdout.write(
                self.style.ERROR(f'  ❌ Input validation test failed: {str(e)}')
            )
        
        # Test schema validation
        schemas_to_test = [
            ('LOGIN_SCHEMA', {'email': 'test@example.com', 'password': 'validpassword123'}),
            ('USER_REGISTRATION_SCHEMA', {
                'email': 'new@example.com',
                'password': 'strongpassword123',
                'first_name': 'John',
                'last_name': 'Doe'
            })
        ]
        
        for schema_name, test_data in schemas_to_test:
            try:
                schema = ValidationSchemas.get_schema(schema_name)
                result = validator.validate_and_sanitize(test_data, schema)
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ {schema_name} validation passed')
                )
            except ValidationError as e:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ {schema_name} validation failed: {str(e)}')
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ {schema_name} test error: {str(e)}')
                )