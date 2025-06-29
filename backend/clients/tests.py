from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from authentication.models import User
from organization.models import Organization
from permissions.models import Role
from .models import Client

class ClientAPITests(APITestCase):

    def setUp(self):
        # Orgs
        self.org1 = Organization.objects.create(name='Org 1')
        self.org2 = Organization.objects.create(name='Org 2')

        # Super Admin
        self.super_admin_role = Role.objects.create(name='Super Admin')
        self.super_admin = User.objects.create_user(
            email='superadmin@test.com',
            username='superadmin',
            password='password123',
            role=self.super_admin_role,
            is_superuser=True
        )

        # Org 1 Admin and User
        self.org1_admin_role = Role.objects.create(name='Org Admin', organization=self.org1)
        self.org1_admin = User.objects.create_user(
            email='admin1@test.com',
            username='admin1',
            password='password123',
            organization=self.org1,
            role=self.org1_admin_role
        )
        self.org1_user = User.objects.create_user(email='user1@test.com', username='user1', password='password123', organization=self.org1)

        # Org 2 Admin
        self.org2_admin_role = Role.objects.create(name='Org Admin', organization=self.org2)
        self.org2_admin = User.objects.create_user(
            email='admin2@test.com',
            username='admin2',
            password='password123',
            organization=self.org2,
            role=self.org2_admin_role
        )

        # Clients
        self.client1_org1 = Client.objects.create(
            client_name='Client Alpha', 
            email='alpha@test.com',
            organization=self.org1, 
            created_by=self.org1_admin
        )
        self.client2_org2 = Client.objects.create(
            client_name='Client Bravo', 
            email='bravo@test.com',
            organization=self.org2, 
            created_by=self.org2_admin
        )

        self.client_list_url = reverse('client-list')
        self.client_detail_url = reverse('client-detail', kwargs={'pk': self.client1_org1.pk})

    def test_org_admin_can_list_own_clients(self):
        self.client.force_authenticate(user=self.org1_admin)
        response = self.client.get(self.client_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['client_name'], self.client1_org1.client_name)

    def test_org_admin_cannot_list_other_org_clients(self):
        self.client.force_authenticate(user=self.org2_admin)
        response = self.client.get(self.client_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        client_names = [client['client_name'] for client in response.data]
        self.assertIn(self.client2_org2.client_name, client_names)
        self.assertNotIn(self.client1_org1.client_name, client_names)
        
    def test_super_admin_can_list_all_clients(self):
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(self.client_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), Client.objects.count())

    def test_regular_user_cannot_list_clients(self):
        self.client.force_authenticate(user=self.org1_user)
        response = self.client.get(self.client_list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_org_admin_can_create_client(self):
        self.client.force_authenticate(user=self.org1_admin)
        data = {'client_name': 'Client Gamma', 'email': 'gamma@test.com', 'phone_number': '+1234567890'}
        response = self.client.post(self.client_list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertTrue(Client.objects.filter(client_name='Client Gamma', organization=self.org1).exists())

    def test_org_admin_can_update_client(self):
        self.client.force_authenticate(user=self.org1_admin)
        data = {'client_name': 'Client Alpha Updated', 'email': 'alpha@test.com', 'phone_number': '+1234567890'}
        response = self.client.put(self.client_detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.client1_org1.refresh_from_db()
        self.assertEqual(self.client1_org1.client_name, 'Client Alpha Updated')

    def test_org_admin_can_delete_client(self):
        self.client.force_authenticate(user=self.org1_admin)
        response = self.client.delete(self.client_detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Client.objects.filter(pk=self.client1_org1.pk).exists())

    def test_org_admin_cannot_access_other_org_client(self):
        self.client.force_authenticate(user=self.org1_admin)
        other_org_url = reverse('client-detail', kwargs={'pk': self.client2_org2.pk})
        response = self.client.get(other_org_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
