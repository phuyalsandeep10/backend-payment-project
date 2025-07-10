from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from faker import Faker
from organization.models import Organization
from authentication.models import User
from permissions.models import Role

fake = Faker()

class OrganizationEndpointTests(APITestCase):
    def setUp(self):
        # Create a dedicated org and role for the admin
        self.admin_org = Organization.objects.create(name='Admin Org')
        self.admin_role = Role.objects.create(name='SuperAdmin', organization=self.admin_org)
        
        # Create a superuser for admin actions
        self.admin_user = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpassword',
            organization=self.admin_org,
            role=self.admin_role
        )
        
        # Create a regular user and organization for testing
        self.organization = Organization.objects.create(name='Test Org')
        self.role = Role.objects.create(name='Member', organization=self.organization)
        self.user = User.objects.create_user(
            email='user@example.com',
            password='userpassword',
            organization=self.organization,
            role=self.role
        )

        self.list_create_url = reverse('organizations-list')
        self.detail_url = reverse('organizations-detail', kwargs={'pk': self.organization.pk})

    def test_list_organizations_as_admin(self):
        """
        Ensure an admin user can list all organizations.
        """
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Admin can see both organizations
        self.assertEqual(len(response.data), 2)

    def test_list_organizations_as_regular_user(self):
        """
        Ensure a regular user can only list their own organization.
        """
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Regular user can only see their own organization
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], self.organization.name)

    def test_retrieve_organization_as_member(self):
        """
        Ensure a user who is a member of an organization can retrieve it.
        """
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.organization.name)

    def test_create_organization_as_admin(self):
        """
        Ensure an admin can create a new organization.
        """
        self.client.force_authenticate(user=self.admin_user)
        data = {'name': fake.company()}
        response = self.client.post(self.list_create_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Organization.objects.filter(name=data['name']).exists())

    def test_create_organization_unauthenticated(self):
        """
        Ensure an unauthenticated user cannot create an organization.
        """
        data = {'name': fake.company()}
        response = self.client.post(self.list_create_url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_organization_as_admin(self):
        """
        Ensure an admin can update an organization's details.
        """
        self.client.force_authenticate(user=self.admin_user)
        update_data = {'name': 'Updated Org Name'}
        response = self.client.put(self.detail_url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.name, 'Updated Org Name')

    def test_delete_organization_as_admin(self):
        """
        Ensure an admin can delete an organization after its dependent objects are removed.
        """
        self.client.force_authenticate(user=self.admin_user)
        
        # Create a new organization with a user and role to delete
        org_to_delete = Organization.objects.create(name='Org To Delete')
        role_to_delete = Role.objects.create(name='Role To Delete', organization=org_to_delete)
        user_to_delete = User.objects.create_user(
            email='deleteme@example.com',
            password='password',
            organization=org_to_delete,
            role=role_to_delete
        )
        
        detail_url = reverse('organizations-detail', kwargs={'pk': org_to_delete.pk})

        # First, delete the user that depends on the role
        user_to_delete.delete()
        
        # Then, delete the role that depends on the organization
        role_to_delete.delete()
        
        # Now, deleting the organization should succeed
        response = self.client.delete(detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Organization.objects.filter(pk=org_to_delete.pk).exists()) 