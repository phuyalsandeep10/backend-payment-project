from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from .models import User

# Create your tests here.

class AuthTests(APITestCase):
    """
    Test suite for the authentication app.
    """
    def setUp(self):
        self.user = User.objects.create_user(
            email='testuser@example.com',
            username='testuser', 
            password='testpassword'
        )
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.valid_payload = {
            'email': 'testuser@example.com',
            'password': 'testpassword'
        }

    def test_successful_login(self):
        """
        Ensure a user can log in with valid credentials.
        """
        response = self.client.post(self.login_url, self.valid_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)

    def test_failed_login(self):
        """
        Ensure login fails with invalid credentials.
        """
        invalid_payload = {
            'email': 'testuser@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, invalid_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_successful_logout(self):
        """
        Ensure a logged-in user can successfully log out.
        """
        # First, log in to get a token
        login_response = self.client.post(self.login_url, self.valid_payload, format='json')
        token = login_response.data['token']
        
        # Authenticate the client with the token
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        
        # Now, attempt to log out
        logout_response = self.client.post(self.logout_url)
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)

    def test_logout_without_authentication(self):
        """
        Ensure the logout endpoint requires authentication.
        """
        response = self.client.post(self.logout_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
