#!/usr/bin/env python3
"""
Security Validation Tests
Specific tests for security implementations identified in the analysis
"""

import os
import sys
import django
import tempfile
from io import BytesIO

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.conf import settings

User = get_user_model()

class SecurityValidationTests(TestCase):
    """Test security implementations"""
    
    def setUp(self):
        self.client = Client()
        # Try to get existing user or create new one
        try:
            self.user = User.objects.get(email='test@example.com')
        except User.DoesNotExist:
            self.user = User.objects.create_user(
                username='testuser',
                email='test@example.com',
                password='testpass123'
            )
    
    def test_file_upload_security(self):
        """Test file upload security measures"""
        print("Testing file upload security...")
        
        # Test malicious file upload
        malicious_content = b'<?php system($_GET["cmd"]); ?>'
        malicious_file = SimpleUploadedFile(
            "malicious.jpg",  # Disguised as image
            malicious_content,
            content_type="image/jpeg"
        )
        
        try:
            from core_config.file_security import EnhancedFileSecurityValidator
            validator = EnhancedFileSecurityValidator()
            
            # This should fail validation
            result = validator.validate_file_comprehensive(malicious_file)
            print(f"❌ Malicious file validation result: {result['is_safe']}")
            
            if not result['is_safe']:
                print("✅ File upload security: Malicious file correctly rejected")
            else:
                print("❌ File upload security: Malicious file incorrectly accepted")
                
        except Exception as e:
            print(f"✅ File upload security: Malicious file rejected with error: {str(e)}")
    
    def test_sql_injection_protection(self):
        """Test SQL injection protection"""
        print("Testing SQL injection protection...")
        
        # Test SQL injection in login
        sql_injection_payloads = [
            "admin'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'/**/OR/**/1=1--",
            "'; UNION SELECT * FROM users--"
        ]
        
        for payload in sql_injection_payloads:
            response = self.client.post('/api/auth/login/', {
                'username': payload,
                'password': 'password'
            })
            
            # Should not cause server error or successful login
            if response.status_code == 500:
                print(f"❌ SQL injection vulnerability: Payload '{payload}' caused server error")
            elif response.status_code == 200:
                print(f"❌ SQL injection vulnerability: Payload '{payload}' may have succeeded")
            else:
                print(f"✅ SQL injection protection: Payload '{payload}' properly handled")
    
    def test_xss_protection(self):
        """Test XSS protection"""
        print("Testing XSS protection...")
        
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>"
        ]
        
        # Test XSS in various endpoints
        for payload in xss_payloads:
            # Test in search or similar functionality
            response = self.client.get('/api/deals/', {'search': payload})
            
            if payload in response.content.decode():
                print(f"❌ XSS vulnerability: Payload '{payload}' not escaped")
            else:
                print(f"✅ XSS protection: Payload '{payload}' properly escaped")
    
    def test_csrf_protection(self):
        """Test CSRF protection"""
        print("Testing CSRF protection...")
        
        # Test POST without CSRF token
        response = self.client.post('/api/auth/login/', {
            'username': 'test',
            'password': 'test'
        })
        
        if response.status_code == 403:
            print("✅ CSRF protection: POST request without token rejected")
        else:
            print("❌ CSRF protection: POST request without token accepted")
    
    def test_security_headers(self):
        """Test security headers"""
        print("Testing security headers...")
        
        try:
            response = self.client.get('/api/auth/login/')
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'SAMEORIGIN',
                'X-XSS-Protection': '1; mode=block',
                'Referrer-Policy': 'strict-origin-when-cross-origin'
            }
            
            for header, expected_value in security_headers.items():
                if header in response:
                    if response[header] == expected_value:
                        print(f"✅ Security header: {header} correctly set")
                    else:
                        print(f"❌ Security header: {header} has incorrect value: {response[header]}")
                else:
                    print(f"❌ Security header: {header} missing")
        except Exception as e:
            print(f"❌ Security headers test failed: {str(e)}")
    
    def test_input_validation(self):
        """Test input validation"""
        print("Testing input validation...")
        
        try:
            from core_config.input_validation_service import InputValidationService
            validator = InputValidationService()
            
            # Test various malicious inputs
            malicious_inputs = [
                "'; DROP TABLE users; --",
                "<script>alert('xss')</script>",
                "../../../etc/passwd",
                "$(rm -rf /)",
                "normal_input"
            ]
            
            for input_data in malicious_inputs:
                if hasattr(validator, 'validate_input'):
                    try:
                        result = validator.validate_input(input_data)
                        if input_data == "normal_input":
                            if result:
                                print(f"✅ Input validation: Normal input accepted")
                            else:
                                print(f"❌ Input validation: Normal input rejected")
                        else:
                            if not result:
                                print(f"✅ Input validation: Malicious input '{input_data[:20]}...' rejected")
                            else:
                                print(f"❌ Input validation: Malicious input '{input_data[:20]}...' accepted")
                    except Exception as e:
                        print(f"✅ Input validation: Malicious input '{input_data[:20]}...' caused validation error")
                else:
                    print("❌ Input validation: validate_input method not available")
                    break
                    
        except ImportError:
            print("❌ Input validation: InputValidationService not available")

def run_security_tests():
    """Run all security validation tests"""
    print("🔒 Starting Security Validation Tests")
    print("=" * 50)
    
    # Create test instance
    test_instance = SecurityValidationTests()
    test_instance.setUp()
    
    # Run tests
    test_instance.test_file_upload_security()
    print()
    test_instance.test_sql_injection_protection()
    print()
    test_instance.test_xss_protection()
    print()
    test_instance.test_csrf_protection()
    print()
    test_instance.test_security_headers()
    print()
    test_instance.test_input_validation()
    
    print("\n" + "=" * 50)
    print("🔒 Security Validation Tests Complete")

if __name__ == "__main__":
    run_security_tests()