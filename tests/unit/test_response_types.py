"""
Tests to verify that all authentication views return proper DRF Response objects.
This helps prevent ContentNotRenderedError issues.
"""

import json
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from django.template.response import TemplateResponse
from django.http import HttpResponse, JsonResponse
from unittest.mock import patch, MagicMock

from authentication.models import User, UserSession
from organization.models import Organization
from permissions.models import Role

User = get_user_model()

class AuthenticationResponseTypeTests(APITestCase):
    """Test that all authentication endpoints return proper DRF Response objects."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test organization
        self.organization = Organization.objects.create(
            name="Test Organization"
        )
        
        # Create test roles
        self.admin_role = Role.objects.create(
            name="Organization Admin",
            organization=self.organization
        )
        
        self.user_role = Role.objects.create(
            name="Salesperson",
            organization=self.organization
        )
        
        # Create test users
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            first_name="Admin",
            last_name="User",
            organization=self.organization,
            role=self.admin_role
        )
        
        self.regular_user = User.objects.create_user(
            email="user@test.com",
            password="testpass123",
            first_name="Regular",
            last_name="User",
            organization=self.organization,
            role=self.user_role
        )
        
        self.super_user = User.objects.create_superuser(
            email="super@test.com",
            password="testpass123",
            first_name="Super",
            last_name="User"
        )
    
    def test_login_view_response_type(self):
        """Test that login view returns DRF Response."""
        url = reverse('authentication:login')
        data = {
            'email': 'user@test.com',
            'password': 'testpass123'
        }
        
        response = self.client.post(url, data, format='json')
        
        # Should be a DRF Response, not TemplateResponse or HttpResponse
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertNotIsInstance(response, HttpResponse)
        
        # Should have proper content type
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_register_view_response_type(self):
        """Test that register view returns DRF Response."""
        url = reverse('authentication:register')
        data = {
            'email': 'newuser@test.com',
            'password': 'newpass123',
            'first_name': 'New',
            'last_name': 'User'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_logout_view_response_type(self):
        """Test that logout view returns DRF Response."""
        # Create token for user
        token = Token.objects.create(user=self.regular_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        url = reverse('authentication:logout')
        response = self.client.post(url)
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_password_change_view_response_type(self):
        """Test that password change view returns DRF Response."""
        token = Token.objects.create(user=self.regular_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        url = reverse('authentication:password_change')
        data = {
            'old_password': 'testpass123',
            'new_password': 'newpass456'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    @patch('authentication.views.send_otp_email')
    @patch('authentication.views.generate_otp')
    def test_super_admin_login_response_type(self, mock_generate_otp, mock_send_otp):
        """Test that super admin login returns DRF Response."""
        mock_generate_otp.return_value = '123456'
        
        url = reverse('authentication:super_admin_login')
        data = {
            'email': 'super@test.com',
            'password': 'testpass123'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    @patch('authentication.views.send_otp_email')
    @patch('authentication.views.generate_otp')
    def test_org_admin_login_response_type(self, mock_generate_otp, mock_send_otp):
        """Test that org admin login returns DRF Response."""
        mock_generate_otp.return_value = '123456'
        
        url = reverse('authentication:org_admin_login')
        data = {
            'email': 'admin@test.com',
            'password': 'testpass123'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_health_check_response_type(self):
        """Test that health check returns proper response type."""
        url = reverse('authentication:health_check')
        response = self.client.get(url)
        
        # Health check uses JsonResponse, but should be converted by decorator
        self.assertTrue(
            isinstance(response, (Response, JsonResponse)),
            f"Expected Response or JsonResponse, got {type(response)}"
        )
        
        # Should have JSON content type
        self.assertIn('application/json', response['Content-Type'])
    
    def test_user_profile_view_response_type(self):
        """Test that user profile view returns DRF Response."""
        token = Token.objects.create(user=self.regular_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        url = reverse('authentication:profile')
        response = self.client.get(url)
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_set_sales_target_response_type(self):
        """Test that set sales target view returns DRF Response."""
        token = Token.objects.create(user=self.regular_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        url = reverse('authentication:set_sales_target')
        data = {'sales_target': '10000.00'}
        
        response = self.client.post(url, data, format='json')
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_login_stats_response_type(self):
        """Test that login stats view returns DRF Response."""
        token = Token.objects.create(user=self.regular_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        url = reverse('authentication:login_stats')
        response = self.client.get(url)
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')

class ResponseValidatorTests(TestCase):
    """Test the response validation decorators."""
    
    def test_validate_response_type_decorator(self):
        """Test that the validate_response_type decorator works correctly."""
        from authentication.response_validators import validate_response_type
        
        # Mock view that returns TemplateResponse
        @validate_response_type
        def mock_view_with_template_response():
            template_response = TemplateResponse(
                request=MagicMock(),
                template='test.html',
                context={'test': 'data'}
            )
            template_response.render = MagicMock()
            template_response.status_code = 200
            template_response.content = b'{"test": "data"}'
            return template_response
        
        response = mock_view_with_template_response()
        
        # Should be converted to DRF Response
        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 200)
    
    def test_ensure_drf_response_decorator(self):
        """Test that the ensure_drf_response decorator works correctly."""
        from authentication.response_validators import ensure_drf_response
        
        # Mock view that returns JsonResponse
        @ensure_drf_response
        def mock_view_with_json_response():
            return JsonResponse({'test': 'data'})
        
        response = mock_view_with_json_response()
        
        # Should be converted to DRF Response
        self.assertIsInstance(response, Response)
        self.assertEqual(response.data, {'test': 'data'})
    
    def test_log_response_type_decorator(self):
        """Test that the log_response_type decorator logs correctly."""
        from authentication.response_validators import log_response_type
        
        @log_response_type
        def mock_view():
            return Response({'test': 'data'})
        
        with patch('authentication.response_validators.security_logger') as mock_logger:
            response = mock_view()
            
            # Should log the response type
            mock_logger.debug.assert_called_once()
            self.assertIn('Response type for mock_view', mock_logger.debug.call_args[0][0])
            
            # Should return the original response
            self.assertIsInstance(response, Response)
            self.assertEqual(response.data, {'test': 'data'})

class PasswordViewsResponseTypeTests(APITestCase):
    """Test that password management views return proper DRF Response objects."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test organization
        self.organization = Organization.objects.create(
            name="Test Organization"
        )
        
        # Create admin role
        self.admin_role = Role.objects.create(
            name="Organization Admin",
            organization=self.organization
        )
        
        # Create admin user
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            first_name="Admin",
            last_name="User",
            organization=self.organization,
            role=self.admin_role
        )
        
        # Create token for admin user
        self.token = Token.objects.create(user=self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
    
    def test_password_policy_dashboard_response_type(self):
        """Test that password policy dashboard returns DRF Response."""
        url = reverse('authentication:password_policy_dashboard')
        response = self.client.get(url)
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_validate_password_strength_response_type(self):
        """Test that validate password strength returns DRF Response."""
        url = reverse('authentication:validate_password_strength')
        data = {'password': 'testpassword123'}
        
        response = self.client.post(url, data, format='json')
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_password_analytics_response_type(self):
        """Test that password analytics returns DRF Response."""
        url = reverse('authentication:password_analytics')
        response = self.client.get(url)
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_force_password_reset_organization_response_type(self):
        """Test that force password reset returns DRF Response."""
        url = reverse('authentication:force_password_reset_org')
        response = self.client.post(url, {}, format='json')
        
        self.assertIsInstance(response, Response)
        self.assertNotIsInstance(response, TemplateResponse)
        self.assertEqual(response['Content-Type'], 'application/json')