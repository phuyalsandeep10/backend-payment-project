from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from faker import Faker
from organization.models import Organization
from authentication.models import User
from permissions.models import Role, Permission

fake = Faker()

class RoleEndpointTests(APITestCase):
    def setUp(self):
        # Create a superuser and their organization/role
        self.admin_org = Organization.objects.create(name='Admin Org')
        self.admin_role = Role.objects.create(name='SuperAdmin', organization=self.admin_org)
        self.admin_user = User.objects.create_superuser(
            email='admin@example.com', password='adminpassword',
            organization=self.admin_org, role=self.admin_role
        )

        # Create a regular organization and user for testing permissions
        self.test_org = Organization.objects.create(name='Test Org')
        self.test_role = Role.objects.create(name='OrgAdmin', organization=self.test_org)
        self.org_admin_user = User.objects.create_user(
            email='orgadmin@example.com', password='userpassword',
            organization=self.test_org, role=self.test_role
        )
        
        # Assign a permission to the org admin role
        can_manage_roles = Permission.objects.create(
            name='Can Manage Roles', codename='can_manage_roles'
        )
        self.test_role.permissions.add(can_manage_roles)

        self.list_create_url = reverse('role-list')
        self.detail_url = reverse('role-detail', kwargs={'pk': self.test_role.pk})

    def test_list_roles_as_org_admin(self):
        """
        Ensure a user with appropriate permissions can list roles in their organization.
        """
        self.client.force_authenticate(user=self.org_admin_user)
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only see roles from their own organization
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], self.test_role.name)

    def test_create_role_as_org_admin(self):
        """
        Ensure a user with permissions can create a role in their organization.
        """
        self.client.force_authenticate(user=self.org_admin_user)
        data = {'name': 'Sales Rep', 'organization': self.test_org.pk}
        response = self.client.post(self.list_create_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Role.objects.filter(name='Sales Rep', organization=self.test_org).exists())

    def test_create_role_for_another_org_is_ignored(self):
        """
        Ensure a user attempting to create a role for another organization
        ends up creating it in their own organization instead.
        """
        self.client.force_authenticate(user=self.org_admin_user)
        # Attempt to create a role in the admin's org
        data = {'name': 'Ignored Org Role', 'organization': self.admin_org.pk}
        response = self.client.post(self.list_create_url, data)
        
        # The view should override the organization and create it in the user's org
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify the role was created in the user's actual organization
        self.assertTrue(
            Role.objects.filter(name='Ignored Org Role', organization=self.org_admin_user.organization).exists()
        )
        # Verify it was NOT created in the other organization
        self.assertFalse(
            Role.objects.filter(name='Ignored Org Role', organization=self.admin_org).exists()
        )

    def test_update_role_as_org_admin(self):
        """
        Ensure a user with permissions can update a role.
        """
        self.client.force_authenticate(user=self.org_admin_user)
        update_data = {'name': 'Senior OrgAdmin'}
        response = self.client.patch(self.detail_url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.test_role.refresh_from_db()
        self.assertEqual(self.test_role.name, 'Senior OrgAdmin')

    def test_delete_role_as_org_admin(self):
        """
        Ensure a user with permissions can delete a role.
        """
        # Create a role with no users to avoid ProtectedError
        role_to_delete = Role.objects.create(name='Temporary Role', organization=self.test_org)
        delete_url = reverse('role-detail', kwargs={'pk': role_to_delete.pk})
        
        self.client.force_authenticate(user=self.org_admin_user)
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Role.objects.filter(pk=role_to_delete.pk).exists())

    def test_unauthorized_user_cannot_list_roles(self):
        """
        Ensure a user without the 'can_manage_roles' permission cannot access the endpoint.
        """
        unauthorized_user = User.objects.create_user(email='no-perms@test.com', password='password', organization=self.test_org, role=self.test_role)
        # Create a new role without the specific permission
        basic_role = Role.objects.create(name='Basic', organization=self.test_org)
        unauthorized_user.role = basic_role
        unauthorized_user.save()
        
        self.client.force_authenticate(user=unauthorized_user)
        response = self.client.get(self.list_create_url)
        # A user without the required permission should be forbidden.
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) 