from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from rest_framework.authtoken.models import Token
from faker import Faker
from organization.models import Organization
from authentication.models import User
from permissions.models import Role

fake = Faker()

class OrganizationViewSetTests(APITestCase):
    """Comprehensive tests for OrganizationViewSet."""

    def setUp(self):
        """Set up test data."""
        # Create organizations
        self.org1 = Organization.objects.create(name="Organization 1", description="First org")
        self.org2 = Organization.objects.create(name="Organization 2", description="Second org")
        
        # Create super admin user
        self.super_admin = User.objects.create_superuser(
            email="superadmin@test.com",
            password="adminpass123",
            username="superadmin"
        )
        
        # Create org admin role and user
        self.admin_role = Role.objects.create(name="Org Admin", organization=self.org1)
        self.org_admin = User.objects.create_user(
            email="orgadmin@test.com",
            password="orgpass123",
            username="orgadmin",
            organization=self.org1,
            role=self.admin_role,
            is_staff=True
        )
        
        # Create regular user
        self.user_role = Role.objects.create(name="Member", organization=self.org1)
        self.regular_user = User.objects.create_user(
            email="user@test.com",
            password="userpass123",
            username="user",
            organization=self.org1,
            role=self.user_role
        )
        
        # Create user with no organization
        self.no_org_user = User.objects.create_user(
            email="noorg@test.com",
            password="noorgpass123",
            username="noorguser"
        )
        
        self.list_url = reverse('organizations-list')
        self.detail_url = reverse('organizations-detail', kwargs={'pk': self.org1.pk})

    def test_list_organizations_super_admin(self):
        """Test super admin can list all organizations."""
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
        
        # Check both organizations are returned
        org_names = [org['name'] for org in response.data]
        self.assertIn("Organization 1", org_names)
        self.assertIn("Organization 2", org_names)

    def test_list_organizations_org_admin(self):
        """Test org admin can list all organizations (staff privilege)."""
        self.client.force_authenticate(user=self.org_admin)
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_list_organizations_regular_user(self):
        """Test regular user can only see their own organization."""
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], "Organization 1")

    def test_list_organizations_no_org_user(self):
        """Test user with no organization sees empty list."""
        self.client.force_authenticate(user=self.no_org_user)
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    def test_list_organizations_unauthenticated(self):
        """Test unauthenticated request is rejected."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_retrieve_organization_super_admin(self):
        """Test super admin can retrieve any organization."""
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], "Organization 1")
        self.assertEqual(response.data['description'], "First org")

    def test_retrieve_organization_member(self):
        """Test organization member can retrieve their organization."""
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], "Organization 1")

    def test_retrieve_organization_non_member(self):
        """Test non-member cannot retrieve organization."""
        self.client.force_authenticate(user=self.no_org_user)
        response = self.client.get(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_organization_super_admin(self):
        """Test super admin can create organizations."""
        self.client.force_authenticate(user=self.super_admin)
        data = {
            'name': 'New Organization',
            'description': 'A brand new organization',
            'is_active': True
        }
        
        response = self.client.post(self.list_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Organization')
        
        # Verify organization was created in database
        self.assertTrue(Organization.objects.filter(name='New Organization').exists())

    def test_create_organization_regular_user(self):
        """Test regular user cannot create organizations."""
        self.client.force_authenticate(user=self.regular_user)
        data = {'name': 'Unauthorized Org'}
        
        response = self.client.post(self.list_url, data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_organization_duplicate_name(self):
        """Test creating organization with duplicate name fails."""
        self.client.force_authenticate(user=self.super_admin)
        data = {'name': 'Organization 1'}  # Already exists
        
        response = self.client.post(self.list_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_organization_super_admin(self):
        """Test super admin can update organizations."""
        self.client.force_authenticate(user=self.super_admin)
        data = {
            'name': 'Updated Organization',
            'description': 'Updated description',
            'is_active': False
        }
        
        response = self.client.put(self.detail_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Updated Organization')
        
        # Verify changes in database
        self.org1.refresh_from_db()
        self.assertEqual(self.org1.name, 'Updated Organization')
        self.assertFalse(self.org1.is_active)

    def test_partial_update_organization(self):
        """Test partial update of organization."""
        self.client.force_authenticate(user=self.super_admin)
        data = {'description': 'Partially updated description'}
        
        response = self.client.patch(self.detail_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['description'], 'Partially updated description')
        
        # Verify name remained unchanged
        self.org1.refresh_from_db()
        self.assertEqual(self.org1.name, "Organization 1")

    def test_update_organization_regular_user(self):
        """Test regular user cannot update organizations."""
        self.client.force_authenticate(user=self.regular_user)
        data = {'name': 'Unauthorized Update'}
        
        response = self.client.put(self.detail_url, data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_organization_super_admin(self):
        """Test super admin can delete organizations."""
        self.client.force_authenticate(user=self.super_admin)
        
        # Create a new organization to delete (avoid affecting other tests)
        org_to_delete = Organization.objects.create(name="Delete Me Org")
        delete_url = reverse('organizations-detail', kwargs={'pk': org_to_delete.pk})
        
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        
        # Verify organization was deleted
        self.assertFalse(Organization.objects.filter(pk=org_to_delete.pk).exists())

    def test_delete_organization_regular_user(self):
        """Test regular user cannot delete organizations."""
        self.client.force_authenticate(user=self.regular_user)
        
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_organization_queryset_prefetch(self):
        """Test that organizations are properly prefetched with roles."""
        # Create some roles for the organization
        Role.objects.create(name="Test Role 1", organization=self.org1)
        Role.objects.create(name="Test Role 2", organization=self.org1)
        
        self.client.force_authenticate(user=self.super_admin)
        
        # This should not cause N+1 queries due to prefetch_related
        with self.assertNumQueries(4):  # Adjust based on actual query count
            response = self.client.get(self.list_url)
            # Access related data to trigger queries if not prefetched
            for org_data in response.data:
                _ = org_data.get('role_count', 0)


class OrganizationRegistrationViewTests(APITestCase):
    """Comprehensive tests for OrganizationRegistrationView."""

    def setUp(self):
        """Set up test data."""
        # Create existing organization and user for uniqueness tests
        self.existing_org = Organization.objects.create(name="Existing Org")
        self.existing_user = User.objects.create_user(
            email="existing@test.com",
            password="testpass123",
            username="existing"
        )
        
        # Create system-wide Org_admin role (required for registration)
        self.org_admin_role = Role.objects.create(name="Org_admin")
        
        self.registration_url = reverse('organization-register')

    def test_successful_organization_registration(self):
        """Test successful organization registration with admin user."""
        data = {
            'name': 'New Company Inc',
            'description': 'A new company registration',
            'admin_first_name': 'John',
            'admin_last_name': 'Doe',
            'admin_email': 'john.doe@newcompany.com',
            'admin_password': 'securepassword123'
        }
        
        response = self.client.post(self.registration_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Check response contains token and user data
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)
        
        # Verify organization was created
        org = Organization.objects.get(name='New Company Inc')
        self.assertEqual(org.description, 'A new company registration')
        
        # Verify admin user was created
        admin_user = User.objects.get(email='john.doe@newcompany.com')
        self.assertEqual(admin_user.first_name, 'John')
        self.assertEqual(admin_user.last_name, 'Doe')
        self.assertEqual(admin_user.organization, org)
        self.assertEqual(admin_user.role, self.org_admin_role)

    def test_registration_without_description(self):
        """Test registration without description."""
        data = {
            'name': 'Company No Desc',
            'admin_first_name': 'Jane',
            'admin_last_name': 'Smith',
            'admin_email': 'jane@company.com',
            'admin_password': 'password123'
        }
        
        response = self.client.post(self.registration_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify organization was created with empty description
        org = Organization.objects.get(name='Company No Desc')
        self.assertEqual(org.description, '')

    def test_registration_duplicate_organization_name(self):
        """Test registration fails with duplicate organization name."""
        data = {
            'name': 'Existing Org',  # Already exists
            'admin_first_name': 'Test',
            'admin_last_name': 'User',
            'admin_email': 'test@test.com',
            'admin_password': 'password123'
        }
        
        response = self.client.post(self.registration_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('name', response.data)

    def test_registration_duplicate_admin_email(self):
        """Test registration fails with duplicate admin email."""
        data = {
            'name': 'Unique Org Name',
            'admin_first_name': 'Test',
            'admin_last_name': 'User',
            'admin_email': 'existing@test.com',  # Already exists
            'admin_password': 'password123'
        }
        
        response = self.client.post(self.registration_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('admin_email', response.data)

    def test_registration_missing_required_fields(self):
        """Test registration fails with missing required fields."""
        incomplete_data = {
            'name': 'Incomplete Org'
            # Missing admin fields
        }
        
        response = self.client.post(self.registration_url, incomplete_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        required_fields = ['admin_first_name', 'admin_last_name', 'admin_email', 'admin_password']
        for field in required_fields:
            self.assertIn(field, response.data)

    def test_registration_invalid_email(self):
        """Test registration fails with invalid email format."""
        data = {
            'name': 'Invalid Email Org',
            'admin_first_name': 'Invalid',
            'admin_last_name': 'Email',
            'admin_email': 'not-an-email',
            'admin_password': 'password123'
        }
        
        response = self.client.post(self.registration_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('admin_email', response.data)

    def test_registration_without_org_admin_role(self):
        """Test registration fails when Org_admin role doesn't exist."""
        # Delete the Org_admin role
        self.org_admin_role.delete()
        
        data = {
            'name': 'No Role Org',
            'admin_first_name': 'No',
            'admin_last_name': 'Role',
            'admin_email': 'norole@test.com',
            'admin_password': 'password123'
        }
        
        response = self.client.post(self.registration_url, data)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertIn('Org_admin', response.data['error'])

    def test_registration_creates_token(self):
        """Test that registration creates an authentication token."""
        data = {
            'name': 'Token Test Org',
            'admin_first_name': 'Token',
            'admin_last_name': 'Test',
            'admin_email': 'token@test.com',
            'admin_password': 'password123'
        }
        
        response = self.client.post(self.registration_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify token was created for the admin user
        admin_user = User.objects.get(email='token@test.com')
        token = Token.objects.get(user=admin_user)
        self.assertEqual(response.data['token'], token.key)


class OrganizationUtilityViewTests(APITestCase):
    """Tests for utility organization endpoints."""

    def setUp(self):
        """Set up test data."""
        self.innovate_org = Organization.objects.create(name="Innovate Inc.")
        self.other_org = Organization.objects.create(name="Other Company")
        
        self.user = User.objects.create_user(
            email="user@test.com",
            password="testpass123",
            username="user"
        )
        
        self.get_innovate_url = reverse('get-innovate-id')

    def test_get_innovate_organization_id_success(self):
        """Test successful retrieval of Innovate Inc. organization ID."""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.get_innovate_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.innovate_org.id)

    def test_get_innovate_organization_id_not_found(self):
        """Test error when Innovate Inc. organization doesn't exist."""
        # Delete the Innovate organization
        self.innovate_org.delete()
        
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.get_innovate_url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('error', response.data)
        self.assertIn('not found', response.data['error'])

    def test_get_innovate_organization_id_unauthenticated(self):
        """Test that unauthenticated users cannot access the endpoint."""
        response = self.client.get(self.get_innovate_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class OrganizationsAliasViewTests(APITestCase):
    """Tests for the organizations alias endpoint."""

    def setUp(self):
        """Set up test data."""
        self.super_admin = User.objects.create_superuser(
            email="superadmin@test.com",
            password="adminpass123",
            username="superadmin"
        )
        
        self.regular_user = User.objects.create_user(
            email="user@test.com",
            password="userpass123",
            username="user"
        )
        
        self.alias_url = reverse('organizations-alias')

    def test_alias_get_delegates_to_viewset(self):
        """Test GET request delegates to OrganizationViewSet.list."""
        Organization.objects.create(name="Test Org 1")
        Organization.objects.create(name="Test Org 2")
        
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(self.alias_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_alias_post_simple_organization(self):
        """Test POST with simple organization data."""
        self.client.force_authenticate(user=self.super_admin)
        data = {
            'name': 'Simple Org',
            'description': 'A simple organization',
            'is_active': True
        }
        
        response = self.client.post(self.alias_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'Simple Org')
        
        # Verify organization was created
        org = Organization.objects.get(name='Simple Org')
        self.assertEqual(org.description, 'A simple organization')
        self.assertTrue(org.is_active)

    def test_alias_post_organization_with_admin(self):
        """Test POST with admin data delegates to OrganizationWithAdminCreateView."""
        self.client.force_authenticate(user=self.super_admin)
        data = {
            'name': 'Org With Admin',
            'description': 'Organization with admin',
            'admin_email': 'admin@orgwithadmin.com',
            'admin_first_name': 'Admin',
            'admin_last_name': 'User',
            'admin_password': 'adminpass123'
        }
        
        response = self.client.post(self.alias_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('organization', response.data)
        self.assertIn('admin_user', response.data)

    def test_alias_post_missing_name(self):
        """Test POST fails without required name field."""
        self.client.force_authenticate(user=self.super_admin)
        data = {'description': 'Missing name'}
        
        response = self.client.post(self.alias_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('name', response.data)

    def test_alias_post_unauthorized(self):
        """Test POST fails for non-super admin users."""
        self.client.force_authenticate(user=self.regular_user)
        data = {'name': 'Unauthorized Org'}
        
        response = self.client.post(self.alias_url, data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) 