from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from authentication.models import User
from organization.models import Organization
from .models import Role, Permission

class PermissionsAPITests(APITestCase):

    def setUp(self):
        # Create Organizations
        self.org1 = Organization.objects.create(name='Org 1')
        self.org2 = Organization.objects.create(name='Org 2')

        # Create a Super Admin
        self.super_admin_role = Role.objects.create(name='Super Admin', organization=None)
        self.super_admin = User.objects.create_user(
            username='superadmin@test.com',
            email='superadmin@test.com',
            password='password123',
            first_name='Super',
            last_name='Admin',
            role=self.super_admin_role,
            is_superuser=True
        )

        # Create an Org Admin for Org 1
        self.org_admin_role_1 = Role.objects.create(name='Org Admin', organization=self.org1)
        self.org_admin_1 = User.objects.create_user(
            username='admin1@test.com',
            email='admin1@test.com',
            password='password123',
            first_name='Admin',
            last_name='One',
            organization=self.org1,
            role=self.org_admin_role_1
        )

        # Create a regular user for Org 1
        self.user_role_1 = Role.objects.create(name='User', organization=self.org1)
        self.regular_user_1 = User.objects.create_user(
            username='user1@test.com',
            email='user1@test.com',
            password='password123',
            first_name='User',
            last_name='One',
            organization=self.org1,
            role=self.user_role_1
        )

        # Create an Org Admin for Org 2 for cross-org tests
        self.org_admin_role_2 = Role.objects.create(name='Org Admin', organization=self.org2)
        self.org_admin_2 = User.objects.create_user(
            username='admin2@test.com',
            email='admin2@test.com',
            password='password123',
            first_name='Admin',
            last_name='Two',
            organization=self.org2,
            role=self.org_admin_role_2
        )

        # Create some permissions
        self.perm1 = Permission.objects.create(name='Perm 1', codename='perm1', category='Cat 1')
        self.perm2 = Permission.objects.create(name='Perm 2', codename='perm2', category='Cat 2')
        self.perm3 = Permission.objects.create(name='Perm 3', codename='perm3', category='Cat 1')

        # URLS
        self.roles_list_url = reverse('role-list')
        self.permissions_list_url = reverse('permission-list')

    def test_list_permissions_unauthenticated(self):
        response = self.client.get(self.permissions_list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_permissions_as_regular_user(self):
        self.client.force_authenticate(user=self.regular_user_1)
        response = self.client.get(self.permissions_list_url)
        # Assuming only admins can see permissions list
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_permissions_as_org_admin(self):
        self.client.force_authenticate(user=self.org_admin_1)
        response = self.client.get(self.permissions_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if permissions are grouped by category
        self.assertIn('Cat 1', response.data)
        self.assertIn('Cat 2', response.data)
        self.assertEqual(len(response.data['Cat 1']), 2)
        self.assertEqual(len(response.data['Cat 2']), 1)

    def test_list_permissions_as_super_admin(self):
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(self.permissions_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['Cat 1']), 2)

    # --- Role Management Tests ---

    def test_list_roles_as_super_admin(self):
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(self.roles_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Super admin sees all roles
        self.assertEqual(len(response.data), Role.objects.count())

    def test_list_roles_as_org_admin(self):
        self.client.force_authenticate(user=self.org_admin_1)
        response = self.client.get(self.roles_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Org admin sees their org's roles + system roles
        expected_count = Role.objects.filter(organization=self.org1).count() + Role.objects.filter(organization=None).count()
        self.assertEqual(len(response.data), expected_count)
        # Ensure we don't see roles from other orgs
        for role in response.data:
            self.assertIn(role['organization'], [self.org1.id, None])

    def test_create_role_as_org_admin(self):
        self.client.force_authenticate(user=self.org_admin_1)
        data = {'name': 'Sales', 'permissions': [self.perm1.id]}
        response = self.client.post(self.roles_list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_role = Role.objects.get(name='Sales', organization=self.org1)
        self.assertEqual(new_role.organization, self.org_admin_1.organization)
        self.assertIn(self.perm1, new_role.permissions.all())

    def test_org_admin_cannot_create_role_for_other_org(self):
        self.client.force_authenticate(user=self.org_admin_1)
        data = {'name': 'Evil Role', 'organization': self.org2.id}
        response = self.client.post(self.roles_list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_super_admin_can_create_system_role(self):
        self.client.force_authenticate(user=self.super_admin)
        data = {'name': 'Auditor'} # No organization specified
        response = self.client.post(self.roles_list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Role.objects.filter(name='Auditor', organization=None).exists())

    def test_super_admin_can_create_role_for_specific_org(self):
        self.client.force_authenticate(user=self.super_admin)
        data = {'name': 'Manager', 'organization': self.org2.id}
        response = self.client.post(self.roles_list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Role.objects.filter(name='Manager', organization=self.org2).exists())

    def test_org_admin_can_update_own_org_role(self):
        self.client.force_authenticate(user=self.org_admin_1)
        role_to_update = self.user_role_1
        url = reverse('role-detail', kwargs={'pk': role_to_update.pk})
        data = {'name': 'Power User', 'permissions': [self.perm1.id, self.perm3.id]}
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        role_to_update.refresh_from_db()
        self.assertEqual(role_to_update.name, 'Power User')
        self.assertEqual(role_to_update.permissions.count(), 2)

    def test_org_admin_cannot_update_other_org_role(self):
        self.client.force_authenticate(user=self.org_admin_1)
        role_to_update = self.org_admin_role_2 # From Org 2
        url = reverse('role-detail', kwargs={'pk': role_to_update.pk})
        data = {'name': 'Hacked Role'}
        response = self.client.put(url, data, format='json')
        # This user doesn't even have permission to see this role, so it's 404
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
