import unittest
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from .models import Organization
from authentication.models import User

class OrganizationTests(APITestCase):
    """
    Test suite for the organization registration endpoint.
    """
    def setUp(self):
        self.register_url = reverse('register-organization')
        self.valid_payload = {
            "name": "Test Corp",
            "admin_email": "admin@testcorp.com",
            "admin_password": "strongpassword123"
        }

    def test_successful_registration(self):
        """
        Ensure a new organization and its admin can be created successfully.
        """
        response = self.client.post(self.register_url, self.valid_payload, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertTrue(Organization.objects.filter(name='Test Corp').exists())
        self.assertTrue(User.objects.filter(email='admin@testcorp.com').exists())
        
        admin_user = User.objects.get(email='admin@testcorp.com')
        self.assertEqual(admin_user.organization.name, 'Test Corp')
        self.assertEqual(admin_user.role.name, 'Org Admin')

    def test_duplicate_organization_name(self):
        """
        Ensure registration fails if the organization name already exists.
        """
        Organization.objects.create(name='Test Corp')
        response = self.client.post(self.register_url, self.valid_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('name', response.data)

    def test_duplicate_admin_email(self):
        """
        Ensure registration fails if the admin email already exists.
        """
        User.objects.create_user(email='admin@testcorp.com', password='password')
        response = self.client.post(self.register_url, self.valid_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('admin_email', response.data)
