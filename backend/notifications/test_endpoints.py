import uuid
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from authentication.models import User
from organization.models import Organization
from permissions.models import Role, Permission
from notifications.models import Notification

class NotificationEndpointTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        # Setup Organizations
        cls.organization1 = Organization.objects.create(name="Org 1")

        # Setup Roles
        cls.role1 = Role.objects.create(name='Admin', organization=cls.organization1)
        
        # Setup Users
        cls.user1 = User.objects.create_user(username='user1', email='user1@example.com', password='password123', organization=cls.organization1, role=cls.role1)

    def setUp(self):
        # Authenticate User 1
        self.client.force_authenticate(user=self.user1)

        # Create some notifications
        self.notification1 = Notification.objects.create(
            recipient=self.user1,
            title="Test Notification 1",
            message="This is a test notification.",
            notification_type="system_alert"
        )
        self.notification2 = Notification.objects.create(
            recipient=self.user1,
            title="Test Notification 2",
            message="This is another test notification.",
            notification_type="system_alert",
            is_read=True
        )

        # URLS
        self.list_url = reverse('notifications:notification-list')
        self.detail_url = reverse('notifications:notification-detail', kwargs={'pk': self.notification1.pk})
        self.settings_url = reverse('notifications:notification-settings-list')
        self.mark_as_read_url = reverse('notifications:notification-mark-as-read', kwargs={'pk': self.notification1.pk})

    def test_list_notifications(self):
        """
        A user should be able to list their notifications.
        """
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)

    def test_list_unread_notifications(self):
        """
        A user should be able to filter for unread notifications.
        """
        response = self.client.get(self.list_url, {'unread_only': 'true'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['id'], self.notification1.id)

    def test_mark_notification_as_read(self):
        """
        A user should be able to mark a notification as read.
        """
        self.assertFalse(Notification.objects.get(pk=self.notification1.pk).is_read)
        response = self.client.post(self.mark_as_read_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(Notification.objects.get(pk=self.notification1.pk).is_read)

    def test_retrieve_notification_settings(self):
        """
        A user should be able to retrieve their notification settings.
        """
        response = self.client.get(self.settings_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user'], self.user1.pk) 