import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model
from organization.models import Organization
from permissions.models import Role

User = get_user_model()

class AuthenticationTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.organization = Organization.objects.create(name='Test Organization')
        self.role = Role.objects.create(name='Test Role', organization=self.organization)
        self.register_url = reverse('authentication:register')
        self.login_url = reverse('authentication:direct_login')
        self.logout_url = reverse('authentication:logout')

        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password': 'testpassword123',
            'password_confirm': 'testpassword123',
            'first_name': 'Test',
            'last_name': 'User',
            'organization': self.organization.pk,
            'role': self.role.pk,
        }

    def test_user_registration_success(self):
        """
        Ensure a new user can be registered successfully.
        """
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email=self.user_data['email']).exists())

    def test_user_registration_missing_fields(self):
        """
        Ensure user registration fails if required fields are missing.
        """
        invalid_data = self.user_data.copy()
        del invalid_data['email']
        response = self.client.post(self.register_url, invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_login_success(self):
        """
        Ensure a registered user can log in and get an auth token.
        """
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {'email': self.user_data['email'], 'password': self.user_data['password']}
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    def test_user_login_failure(self):
        """
        Ensure login fails with incorrect credentials.
        """
        login_data = {'email': self.user_data['email'], 'password': 'wrongpassword'}
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_logout(self):
        """
        Ensure a logged-in user can log out.
        """
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {'email': self.user_data['email'], 'password': self.user_data['password']}
        response = self.client.post(self.login_url, login_data, format='json')
        token = response.data['token']
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        logout_response = self.client.post(self.logout_url)
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)

    def test_access_protected_endpoint_with_token(self):
        """
        Ensure a user with a valid token can access a protected endpoint.
        """
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {'email': self.user_data['email'], 'password': self.user_data['password']}
        response = self.client.post(self.login_url, login_data, format='json')
        token = response.data['token']
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        profile_url = reverse('authentication:profile')
        profile_response = self.client.get(profile_url)
        self.assertEqual(profile_response.status_code, status.HTTP_200_OK)

    def test_access_protected_endpoint_without_token(self):
        """
        Ensure a user without a token cannot access a protected endpoint.
        """
        profile_url = reverse('authentication:profile')
        profile_response = self.client.get(profile_url)
        self.assertEqual(profile_response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_password_change_success(self):
        """
        Ensure a user can change their password successfully.
        """
        # Register and log in the user
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {'email': self.user_data['email'], 'password': self.user_data['password']}
        response = self.client.post(self.login_url, login_data, format='json')
        token = response.data['token']
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)

        # Change the password
        password_change_url = reverse('authentication:password_change')
        password_change_data = {
            'current_password': 'testpassword123',
            'new_password': 'newtestpassword123',
            'confirm_password': 'newtestpassword123'
        }
        response = self.client.post(password_change_url, password_change_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Log in with the new password
        new_login_data = {'email': self.user_data['email'], 'password': 'newtestpassword123'}
        response = self.client.post(self.login_url, new_login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_password_change_failure_wrong_old_password(self):
        """
        Ensure password change fails if the old password is incorrect.
        """
        # Register and log in the user
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {'email': self.user_data['email'], 'password': self.user_data['password']}
        response = self.client.post(self.login_url, login_data, format='json')
        token = response.data['token']
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)

        # Attempt to change the password with the wrong old password
        password_change_url = reverse('authentication:password_change')
        password_change_data = {
            'current_password': 'wrongoldpassword',
            'new_password': 'newtestpassword123',
            'confirm_password': 'newtestpassword123'
        }
        response = self.client.post(password_change_url, password_change_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST) 