from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token
import secrets
from .models import User, UserSession, Organization
from permissions.models import Role as OrgRole

class SessionManagementTests(APITestCase):

    def setUp(self):
        """
        Set up the necessary objects for the tests.
        """
        self.organization = Organization.objects.create(name='Test Org')
        self.admin_role = OrgRole.objects.create(name='Admin', organization=self.organization)
        self.member_role = OrgRole.objects.create(name='Member', organization=self.organization)

        self.user1 = User.objects.create_user(
            username='testuser1',
            password='password123',
            email='test1@example.com',
            organization=self.organization,
            org_role=self.admin_role
        )
        self.token1, _ = Token.objects.get_or_create(user=self.user1)

        self.user2 = User.objects.create_user(
            username='testuser2',
            password='password123',
            email='test2@example.com',
            organization=self.organization,
            org_role=self.member_role
        )
        self.token2, _ = Token.objects.get_or_create(user=self.user2)

    def test_session_creation_on_login(self):
        """
        Ensure a UserSession is created upon successful login.
        """
        # Ensure no sessions exist for the user initially
        self.assertEqual(UserSession.objects.filter(user=self.user1).count(), 0)

        url = reverse('login')
        data = {'username': 'testuser1', 'password': 'password123'}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Now, one session should exist
        self.assertEqual(UserSession.objects.filter(user=self.user1).count(), 1)
        # The session key should match the user's token key
        self.assertTrue(UserSession.objects.filter(user=self.user1, session_key=self.token1.key).exists())

    def test_list_own_sessions(self):
        """
        Ensure a user can list their own sessions.
        """
        # Create a session for user1 to test with
        session1 = UserSession.objects.create(
            user=self.user1,
            session_key=self.token1.key,
            ip_address='127.0.0.1',
            user_agent='TestAgent/1.0'
        )

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token1.key)
        url = reverse('usersession-list')
        response = self.client.get(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['ip_address'], session1.ip_address)

    def test_cannot_list_other_user_sessions(self):
        """
        Ensure a user cannot list sessions belonging to another user.
        """
        # Create a session for user1
        UserSession.objects.create(
            user=self.user1,
            session_key=self.token1.key,
            ip_address='127.0.0.1',
            user_agent='TestAgent/1.0'
        )

        # user2 tries to list user1's sessions - should get an empty list
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2.key)
        url = reverse('usersession-list')
        response = self.client.get(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    def test_revoke_own_session(self):
        """
        Ensure a user can revoke one of their own sessions.
        """
        # This is the "current" session the user is authenticated with
        UserSession.objects.create(
            user=self.user1,
            session_key=self.token1.key,
            ip_address='127.0.0.1',
            user_agent='TestAgent/1.0'
        )
        # This is another session that we want to revoke
        session_to_revoke = UserSession.objects.create(
            user=self.user1,
            session_key=secrets.token_hex(20),
            ip_address='192.168.1.1',
            user_agent='AnotherAgent/2.0'
        )

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token1.key)
        url = reverse('usersession-detail', kwargs={'pk': session_to_revoke.pk})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(UserSession.objects.filter(pk=session_to_revoke.pk).exists())

    def test_cannot_revoke_current_session(self):
        """
        Ensure a user cannot revoke their current, active session.
        """
        # Create the session that corresponds to the token being used
        current_session = UserSession.objects.create(
            user=self.user1,
            session_key=self.token1.key,
            ip_address='127.0.0.1',
            user_agent='TestAgent/1.0'
        )

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token1.key)
        url = reverse('usersession-detail', kwargs={'pk': current_session.pk})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'You cannot revoke your current session.')
        self.assertTrue(UserSession.objects.filter(pk=current_session.pk).exists())

    def test_cannot_revoke_other_user_session(self):
        """
        Ensure a user cannot revoke a session belonging to another user.
        """
        # Create a session for user1
        session1 = UserSession.objects.create(
            user=self.user1,
            session_key=self.token1.key,
            ip_address='127.0.0.1',
            user_agent='TestAgent/1.0'
        )

        # user2 tries to revoke user1's session
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token2.key)
        url = reverse('usersession-detail', kwargs={'pk': session1.pk})
        response = self.client.delete(url)

        # Should return 404 Not Found because the query for the object will fail
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertTrue(UserSession.objects.filter(pk=session1.pk).exists())
