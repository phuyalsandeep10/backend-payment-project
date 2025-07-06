from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from faker import Faker
from organization.models import Organization
from authentication.models import User
from permissions.models import Role, Permission
from .models import Client

fake = Faker()

class ClientEndpointTests(APITestCase):
    def setUp(self):
        # Create a user and organization
        self.organization = Organization.objects.create(name='Test Org')
        self.role = Role.objects.create(name='Sales', organization=self.organization)
        
        # Create and assign the necessary permissions
        permissions_to_create = [
            {'name': 'View All Clients', 'codename': 'view_all_clients'},
            {'name': 'Create Client', 'codename': 'create_client'},
            {'name': 'Edit Client Details', 'codename': 'edit_client_details'},
            {'name': 'Delete Client', 'codename': 'delete_client'},
        ]
        for perm_data in permissions_to_create:
            permission, _ = Permission.objects.get_or_create(**perm_data)
            self.role.permissions.add(permission)
        
        self.user = User.objects.create_user(
            email='user@example.com',
            password='userpassword',
            organization=self.organization,
            role=self.role
        )
        self.client.force_authenticate(user=self.user)

        # Create a client belonging to the organization and created by the user
        self.client_record = Client.objects.create(
            organization=self.organization,
            created_by=self.user,
            client_name=fake.name(),
            email=fake.email(),
            phone_number=fake.phone_number()
        )

        self.list_create_url = reverse('client-list')
        self.detail_url = reverse('client-detail', kwargs={'pk': self.client_record.pk})

    def test_list_clients(self):
        """
        Ensure an authenticated user can list clients in their organization.
        """
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['client_name'], self.client_record.client_name)

    def test_create_client(self):
        """
        Ensure a user can create a client, who is automatically assigned to their org.
        """
        data = {
            'client_name': fake.name(),
            'email': fake.email(),
            'phone_number': fake.msisdn()
        }
        response = self.client.post(self.list_create_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Client.objects.filter(email=data['email'], organization=self.organization).exists())

    def test_retrieve_client(self):
        """
        Ensure a user can retrieve a client from their own organization.
        """
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.client_record.email)

    def test_cannot_retrieve_client_from_another_org(self):
        """
        Ensure a user cannot retrieve a client from a different organization.
        """
        # Create a client in another org
        other_org = Organization.objects.create(name='Other Org')
        # This other client needs a creator as well
        other_user = User.objects.create_user(email='other@user.com', password='password', organization=other_org, role=self.role)
        other_client = Client.objects.create(
            organization=other_org,
            created_by=other_user,
            client_name='Secret Client'
        )
        other_detail_url = reverse('client-detail', kwargs={'pk': other_client.pk})
        
        response = self.client.get(other_detail_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_client(self):
        """
        Ensure a user can update a client in their organization.
        """
        update_data = {'client_name': 'Updated Client Name'}
        response = self.client.patch(self.detail_url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.client_record.refresh_from_db()
        self.assertEqual(self.client_record.client_name, 'Updated Client Name')

    def test_delete_client(self):
        """
        Ensure a user can delete a client in their organization.
        """
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Client.objects.filter(pk=self.client_record.pk).exists())

    def test_unauthenticated_user_cannot_access(self):
        """
        Ensure unauthenticated users cannot access any client endpoints.
        """
        self.client.logout()
        response_list = self.client.get(self.list_create_url)
        response_create = self.client.post(self.list_create_url, {})
        response_detail = self.client.get(self.detail_url)
        
        self.assertEqual(response_list.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response_create.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response_detail.status_code, status.HTTP_401_UNAUTHORIZED) 