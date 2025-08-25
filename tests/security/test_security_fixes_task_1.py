#!/usr/bin/env python3
"""
Test script for Task 1.1.1 and 1.2.1 - SQL Injection Prevention and File Security Enhancement
"""
import os
import sys
import django
import tempfile
from io import BytesIO

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase, RequestFactory
from django.http import HttpRequest
from django.core.files.uploadedfile import SimpleUploadedFile
from core_config.sql_injection_middleware import SQLInjectionDetectionMiddleware
from core_config.file_security import EnhancedFileSecurityValidator
# from core_config.enhanced_file_security import EnhancedFileSecurityValidator as EnhancedValidator2


class SecurityFixesTest:
    """Test security fixes implementation"""
    
    def __init__(self):
        self.factory = RequestFactory()
        self.sql_middleware = SQLInjectionDetectionMiddleware(lambda r: None)
        self.file_validator = EnhancedFileSecurityValidator()
        self.results = {
            'sql_injection_tests': [],
            'file_security_tests': [],
            'overall_status': 'pending'
        }
    
    def run_all_tests(self):
        """Run all security tests"""
        print("🔒 Testing Security Fixes Implementation")
        print("=" * 60)
        
        try:
            # Test SQL injection detection
            print("\n1. Testing SQL Injection Detection Middleware...")
            self.test_sql_injection_detection()
            
            # Test file security enhancements
            print("\n2. Testing Enhanced File Security Validation...")
            self.test_file_security_enhancements()
            
            # Summary
            self.print_test_summary()
            
            return self.results
            
        except Exception as e:
            print(f"\n❌ Test execution failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection middleware"""
        test_cases = [
            # Safe requests
            {
                'name': 'Safe GET request',
                'method': 'GET',
                'path': '/api/users/',
                'params': {'name': 'john', 'age': '25'},
                'should_block': False
            },
            {
                'name': 'Safe POST request',
                'method': 'POST',
                'path': '/api/deals/',
                'data': {'title': 'New Deal', 'amount': '1000.00'},
                'content_type': 'application/x-www-form-urlencoded',
                'should_block': False
            },
            
            # SQL injection attempts
            {
                'name': 'SQL injection in GET params',
                'method': 'GET',
                'path': '/api/users/',
                'params': {'name': "'; DROP TABLE users; --", 'age': '25'},
                'should_block': True
            },
            {
                'name': 'UNION SELECT attack',
                'method': 'GET',
                'path': '/api/deals/',
                'params': {'search': "' UNION SELECT password FROM users --"},
                'should_block': True
            },
            {
                'name': 'SQL injection in POST data',
                'method': 'POST',
                'path': '/api/login/',
                'data': {'username': 'admin', 'password': "' OR '1'='1' --"},
                'should_block': True
            },
            {
                'name': 'INSERT injection attempt',
                'method': 'POST',
                'path': '/api/comments/',
                'data': {'comment': "'; INSERT INTO admin_users VALUES ('hacker', 'password'); --"},
                'should_block': True
            }
        ]
        
        for test_case in test_cases:
            try:
                # Create request
                if test_case['method'] == 'GET':
                    request = self.factory.get(test_case['path'], test_case.get('params', {}))
                else:
                    request = self.factory.post(
                        test_case['path'], 
                        test_case.get('data', {}),
                        content_type=test_case.get('content_type', 'application/x-www-form-urlencoded')
                    )
                
                # Test middleware
                response = self.sql_middleware.process_request(request)
                
                # Check result
                was_blocked = response is not None
                test_passed = was_blocked == test_case['should_block']
                
                result = {
                    'name': test_case['name'],
                    'expected_block': test_case['should_block'],
                    'was_blocked': was_blocked,
                    'passed': test_passed
                }
                
                self.results['sql_injection_tests'].append(result)
                
                status = "✅ PASS" if test_passed else "❌ FAIL"
                print(f"  {status} - {test_case['name']}")
                
            except Exception as e:
                print(f"  ❌ ERROR - {test_case['name']}: {str(e)}")
                self.results['sql_injection_tests'].append({
                    'name': test_case['name'],
                    'error': str(e),
                    'passed': False
                })
    
    def test_file_security_enhancements(self):
        """Test enhanced file security validation"""
        test_cases = [
            # Safe files
            {
                'name': 'Safe PNG image',
                'filename': 'test.png',
                'content': b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde',
                'should_pass': True
            },
            {
                'name': 'Safe JPEG image',
                'filename': 'photo.jpg',
                'content': b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb',
                'should_pass': True
            },
            {
                'name': 'Safe PDF document',
                'filename': 'document.pdf',
                'content': b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj',
                'should_pass': True
            },
            
            # Malicious files
            {
                'name': 'Script injection in image',
                'filename': 'malicious.png',
                'content': b'\x89PNG\r\n\x1a\n<script>alert("xss")</script>',
                'should_pass': False
            },
            {
                'name': 'Executable disguised as image',
                'filename': 'fake.jpg',
                'content': b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00',
                'should_pass': False
            },
            {
                'name': 'SQL injection in filename',
                'filename': "'; DROP TABLE files; --.jpg",
                'content': b'\xff\xd8\xff\xe0\x00\x10JFIF',
                'should_pass': False
            },
            {
                'name': 'Polyglot file (PNG + HTML)',
                'filename': 'polyglot.png',
                'content': b'\x89PNG\r\n\x1a\n<html><script>malicious()</script></html>',
                'should_pass': False
            }
        ]
        
        for test_case in test_cases:
            try:
                # Create uploaded file
                uploaded_file = SimpleUploadedFile(
                    test_case['filename'],
                    test_case['content'],
                    content_type='application/octet-stream'
                )
                
                # Test validation
                validation_passed = True
                error_message = None
                validation_result = None
                
                try:
                    # Test if the _validate_mime_type_enhanced method exists and works
                    if hasattr(self.file_validator, '_validate_mime_type_enhanced'):
                        result = {'extension': os.path.splitext(test_case['filename'])[1].lower()}
                        self.file_validator._validate_mime_type_enhanced(uploaded_file, result)
                        print(f"    MIME validation result: {result.get('checks_passed', [])}")
                    else:
                        print(f"    ⚠️  _validate_mime_type_enhanced method not found")
                    
                    # Test full validation using the class method
                    validation_result = self.file_validator.validate_file_comprehensive(uploaded_file)
                    
                    # Check if file is considered safe
                    validation_passed = validation_result.get('is_safe', False)
                    if not validation_passed:
                        error_message = f"File validation failed: {validation_result.get('warnings', [])} | {validation_result.get('bypass_attempts', [])}"
                    
                except Exception as e:
                    validation_passed = False
                    error_message = str(e)
                
                # Check result
                test_passed = validation_passed == test_case['should_pass']
                
                result = {
                    'name': test_case['name'],
                    'filename': test_case['filename'],
                    'expected_pass': test_case['should_pass'],
                    'validation_passed': validation_passed,
                    'error_message': error_message,
                    'passed': test_passed
                }
                
                self.results['file_security_tests'].append(result)
                
                status = "✅ PASS" if test_passed else "❌ FAIL"
                print(f"  {status} - {test_case['name']}")
                if error_message and not test_case['should_pass']:
                    print(f"    Expected error: {error_message[:100]}")
                
            except Exception as e:
                print(f"  ❌ ERROR - {test_case['name']}: {str(e)}")
                self.results['file_security_tests'].append({
                    'name': test_case['name'],
                    'error': str(e),
                    'passed': False
                })
    
    def print_test_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        # SQL injection tests summary
        sql_tests = self.results['sql_injection_tests']
        sql_passed = sum(1 for test in sql_tests if test.get('passed', False))
        sql_total = len(sql_tests)
        
        print(f"\n🔒 SQL Injection Detection Tests: {sql_passed}/{sql_total} passed")
        for test in sql_tests:
            if not test.get('passed', False):
                print(f"  ❌ {test['name']}")
                if 'error' in test:
                    print(f"     Error: {test['error']}")
        
        # File security tests summary
        file_tests = self.results['file_security_tests']
        file_passed = sum(1 for test in file_tests if test.get('passed', False))
        file_total = len(file_tests)
        
        print(f"\n📁 File Security Enhancement Tests: {file_passed}/{file_total} passed")
        for test in file_tests:
            if not test.get('passed', False):
                print(f"  ❌ {test['name']}")
                if 'error' in test:
                    print(f"     Error: {test['error']}")
        
        # Overall status
        total_passed = sql_passed + file_passed
        total_tests = sql_total + file_total
        
        if total_passed == total_tests:
            self.results['overall_status'] = 'success'
            print(f"\n🎉 ALL TESTS PASSED ({total_passed}/{total_tests})")
            print("✅ Task 1.1.1 (SQL Injection Prevention) - COMPLETED")
            print("✅ Task 1.2.1 (File Security Enhancement) - COMPLETED")
        else:
            self.results['overall_status'] = 'partial'
            print(f"\n⚠️  SOME TESTS FAILED ({total_passed}/{total_tests} passed)")
            print("🔧 Review failed tests and fix implementation")
        
        print("\n📊 Key Security Improvements:")
        print("  • SQL injection detection middleware added")
        print("  • Enhanced MIME type validation implemented")
        print("  • Polyglot file detection added")
        print("  • Archive bomb detection implemented")
        print("  • Steganography detection added")
        print("  • Raw SQL queries replaced with parameterized queries")


def main():
    """Main function"""
    print("🔒 SECURITY FIXES VALIDATION")
    print("Testing implementation of Tasks 1.1.1 and 1.2.1")
    print("=" * 60)
    
    tester = SecurityFixesTest()
    results = tester.run_all_tests()
    
    if results and results['overall_status'] == 'success':
        print("\n✅ Security fixes validation completed successfully!")
        return True
    else:
        print("\n❌ Security fixes validation failed!")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)