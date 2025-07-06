from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from faker import Faker
from permissions.models import Role
from organization.models import Organization
from rest_framework.authtoken.models import Token

User = get_user_model()
fake = Faker()

class AuthEndpointTests(APITestCase):
    def setUp(self):
        self.register_url = reverse('authentication:register')
        self.login_url = reverse('authentication:direct_login')
        self.profile_url = reverse('authentication:profile')
        self.profile_update_url = reverse('authentication:profile_update')
        self.password_change_url = reverse('authentication:password_change')
        self.logout_url = reverse('authentication:logout')

        # Create prerequisite objects
        self.organization = Organization.objects.create(name='Test Org')
        self.role = Role.objects.create(name='Test Role', organization=self.organization)

        self.user_data = {
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'role': self.role,
            'organization': self.organization
        }
        
        self.password = 'testpassword123'
        self.user = User.objects.create_user(
            email='test@example.com', 
            password=self.password, 
            **self.user_data
        )
        self.user.contact_number = '+1234567890'
        self.user.save()

    def test_user_registration_success(self):
        """
        Ensure a new user can be registered successfully.
        """
        data = {
            'email': fake.email(),
            'username': fake.user_name(),
            'password': 'a_strong_password_123',
            'password_confirm': 'a_strong_password_123',
            'first_name': fake.first_name(),
            'last_name': fake.last_name(),
            'role': self.role.id,
            'organization': self.organization.id
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email=data['email']).exists())

    def test_user_registration_duplicate_email(self):
        """
        Ensure registration fails if the email already exists.
        """
        data = {
            'email': self.user.email,  # Duplicate email
            'username': fake.user_name(),
            'password': 'a_strong_password_123',
            'password_confirm': 'a_strong_password_123',
            'first_name': fake.first_name(),
            'last_name': fake.last_name(),
            'role': self.role.id,
            'organization': self.organization.id
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_registration_missing_fields(self):
        """
        Ensure registration fails if required fields are missing.
        """
        response = self.client.post(self.register_url, {'email': 'onlyemail@example.com', 'password': 'foo'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)

    def test_user_login_success(self):
        """
        Ensure a registered user can log in and receive a token.
        """
        data = {
            'email': self.user.email,
            'password': self.password
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)

    def test_user_login_invalid_credentials(self):
        """
        Ensure login fails with incorrect credentials.
        """
        data = {
            'email': self.user.email,
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_login_nonexistent_user(self):
        """
        Ensure login fails for a user that does not exist.
        """
        data = {
            'email': 'nonexistentuser@example.com',
            'password': 'anypassword'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_user_profile_success(self):
        """
        Ensure an authenticated user can retrieve their own profile.
        """
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user']['email'], self.user.email)

    def test_get_user_profile_unauthenticated(self):
        """
        Ensure an unauthenticated user cannot retrieve a profile.
        """
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_user_profile_success(self):
        """
        Ensure an authenticated user can update their profile.
        """
        self.client.force_authenticate(user=self.user)
        update_data = {'first_name': 'Updated', 'last_name': 'Name', 'contact_number': '+1111111111'}
        response = self.client.put(self.profile_update_url, update_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.contact_number, '+1111111111')

    def test_password_change_success(self):
        """
        Ensure a user can successfully change their password.
        """
        self.client.force_authenticate(user=self.user)
        data = {
            'old_password': self.password,
            'new_password': 'a_new_strong_password_456'
        }
        response = self.client.post(self.password_change_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify the new password works
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(data['new_password']))

    def test_password_change_wrong_old_password(self):
        """
        Ensure password change fails with an incorrect old password.
        """
        self.client.force_authenticate(user=self.user)
        data = {
            'old_password': 'wrong_old_password',
            'new_password': 'a_new_strong_password_456'
        }
        response = self.client.post(self.password_change_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('old_password', response.data)

    def test_user_logout_success(self):
        """
        Ensure a user can log out, invalidating their token.
        """
        token, _ = Token.objects.get_or_create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.post(self.logout_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify token is deleted
        with self.assertRaises(Token.DoesNotExist):
            Token.objects.get(user=self.user) 