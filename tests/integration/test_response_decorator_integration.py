#!/usr/bin/env python
"""
Integration test for response validation decorators on authentication views.
Tests that all critical authentication endpoints properly handle response validation.
"""

import os
import sys
import django
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
import json

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

User = get_user_model()

class ResponseValidationIntegrationTest(APITestCase):
    """Test response validation decorators on authentication views."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test user
        self.test_user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )
        
        # Create superuser
        self.superuser = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='AdminPassword123!'
        )
    
    def test_login_view_response_validation(self):
        """Test that login view returns proper DRF Response."""
        url = '/api/auth/login/'
        data = {
            'email': 'test@example.com',
            'password': 'TestPassword123!'
        }
        
        response = self.client.post(url, data, format='json')
        
        # Should return a proper JSON response (not TemplateResponse)
        self.assertIn('application/json', response.get('Content-Type', ''))
        
        # Should have proper status code
        self.assertIn(response.status_code, [200, 401, 400])
        
        # Response should be JSON parseable
        try:
            json.loads(response.content.decode('utf-8'))
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_register_view_response_validation(self):
        """Test that register view returns proper DRF Response."""
        url = '/api/auth/register/'
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'NewPassword123!',
            'first_name': 'New',
            'last_name': 'User'
        }
        
        response = self.client.post(url, data, format='json')
        
        # Should return a proper JSON response
        self.assertIn('application/json', response.get('Content-Type', ''))
        
        # Should have proper status code
        self.assertIn(response.status_code, [201, 400, 409])
        
        # Response should be JSON parseable
        try:
            json.loads(response.content.decode('utf-8'))
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_logout_view_response_validation(self):
        """Test that logout view returns proper DRF Response."""
        # First login to get a token
        self.client.force_authenticate(user=self.test_user)
        
        url = '/api/auth/logout/'
        response = self.client.post(url, format='json')
        
        # Should return a proper JSON response
        self.assertIn('application/json', response.get('Content-Type', ''))
        
        # Should have proper status code
        self.assertIn(response.status_code, [200, 401])
        
        # Response should be JSON parseable
        try:
            json.loads(response.content.decode('utf-8'))
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_password_change_view_response_validation(self):
        """Test that password change view returns proper DRF Response."""
        self.client.force_authenticate(user=self.test_user)
        
        url = '/api/auth/password-change/'
        data = {
            'old_password': 'TestPassword123!',
            'new_password': 'NewTestPassword123!'
        }
        
        response = self.client.post(url, data, format='json')
        
        # Should return a proper JSON response
        self.assertIn('application/json', response.get('Content-Type', ''))
        
        # Should have proper status code
        self.assertIn(response.status_code, [200, 400, 401])
        
        # Response should be JSON parseable
        try:
            json.loads(response.content.decode('utf-8'))
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_health_check_response_validation(self):
        """Test that health check returns proper response."""
        url = '/api/auth/health/'
        response = self.client.get(url)
        
        # Should return a proper JSON response
        self.assertIn('application/json', response.get('Content-Type', ''))
        
        # Should have proper status code
        self.assertEqual(response.status_code, 200)
        
        # Response should be JSON parseable
        try:
            data = json.loads(response.content.decode('utf-8'))
            self.assertIn('status', data)
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_password_policy_dashboard_response_validation(self):
        """Test password policy dashboard response validation."""
        self.client.force_authenticate(user=self.superuser)
        
        url = '/api/auth/password/policy-dashboard/'
        response = self.client.get(url)
        
        # Should return a proper JSON response
        self.assertIn('application/json', response.get('Content-Type', ''))
        
        # Should have proper status code
        self.assertIn(response.status_code, [200, 400, 403])
        
        # Response should be JSON parseable
        try:
            json.loads(response.content.decode('utf-8'))
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_validate_password_strength_response_validation(self):
        """Test password strength validation response."""
        self.client.force_authenticate(user=self.test_user)
        
        url = '/api/auth/password/validate-strength/'
        data = {'password': 'TestPassword123!'}
        
        response = self.client.post(url, data, format='json')
        
        # Should return a proper JSON response
        self.assertIn('application/json', response.get('Content-Type', ''))
        
        # Should have proper status code
        self.assertIn(response.status_code, [200, 400])
        
        # Response should be JSON parseable
        try:
            data = json.loads(response.content.decode('utf-8'))
            # Should have validation result structure
            self.assertIn('is_valid', data)
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_response_content_type_consistency(self):
        """Test that all authentication endpoints return consistent content types."""
        endpoints_to_test = [
            ('/api/auth/health/', 'GET', None),
            ('/api/auth/login/', 'POST', {'email': 'test@example.com', 'password': 'wrong'}),
            ('/api/auth/register/', 'POST', {'username': '', 'email': 'invalid'}),
        ]
        
        for url, method, data in endpoints_to_test:
            with self.subTest(url=url, method=method):
                if method == 'GET':
                    response = self.client.get(url)
                else:
                    response = self.client.post(url, data or {}, format='json')
                
                # All API responses should be JSON
                content_type = response.get('Content-Type', '')
                self.assertIn('application/json', content_type, 
                             f"Endpoint {url} returned non-JSON content type: {content_type}")
                
                # Should not be a TemplateResponse (which would cause ContentNotRenderedError)
                self.assertNotIn('text/html', content_type,
                                f"Endpoint {url} returned HTML content type: {content_type}")

def run_tests():
    """Run the integration tests."""
    import unittest
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(ResponseValidationIntegrationTest)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    print("Running Response Validation Integration Tests...")
    print("=" * 50)
    
    success = run_tests()
    
    if success:
        print("\n✅ All response validation tests passed!")
    else:
        print("\n❌ Some response validation tests failed!")
    
    sys.exit(0 if success else 1)