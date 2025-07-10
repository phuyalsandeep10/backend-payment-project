from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token
from django.db import transaction
from faker import Faker
from organization.models import Organization
from organization.serializers import OrganizationWithAdminSerializer
from authentication.models import User
from permissions.models import Role

fake = Faker()

class OrganizationWorkflowIntegrationTests(APITestCase):
    """Integration tests for complete organization workflows."""

    def setUp(self):
        """Set up test data."""
        self.super_admin = User.objects.create_superuser(
            email="superadmin@test.com",
            password="adminpass123",
            username="superadmin"
        )
        
        # Create system-wide Org_admin role for registration
        self.system_org_admin_role = Role.objects.create(name="Org_admin")

    def test_complete_organization_registration_workflow(self):
        """Test complete organization registration from start to finish."""
        registration_url = reverse('organization-register')
        
        # Step 1: Register new organization
        registration_data = {
            'name': 'Complete Workflow Corp',
            'description': 'Testing complete workflow',
            'admin_first_name': 'Admin',
            'admin_last_name': 'User',
            'admin_email': 'admin@workflow.com',
            'admin_password': 'securepassword123'
        }
        
        response = self.client.post(registration_url, registration_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify response structure
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)
        token = response.data['token']
        user_data = response.data['user']
        
        # Step 2: Verify organization was created
        org = Organization.objects.get(name='Complete Workflow Corp')
        self.assertEqual(org.description, 'Testing complete workflow')
        
        # Step 3: Verify admin user was created correctly
        admin_user = User.objects.get(email='admin@workflow.com')
        self.assertEqual(admin_user.first_name, 'Admin')
        self.assertEqual(admin_user.last_name, 'User')
        self.assertEqual(admin_user.organization, org)
        self.assertEqual(admin_user.role, self.system_org_admin_role)
        
        # Step 4: Verify token works for authentication
        token_obj = Token.objects.get(key=token)
        self.assertEqual(token_obj.user, admin_user)
        
        # Step 5: Test authenticated request with new token
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        profile_url = reverse('authentication:profile')
        profile_response = self.client.get(profile_url)
        self.assertEqual(profile_response.status_code, status.HTTP_200_OK)
        
        # Step 6: Verify admin can access their organization
        org_detail_url = reverse('organizations-detail', kwargs={'pk': org.pk})
        org_response = self.client.get(org_detail_url)
        self.assertEqual(org_response.status_code, status.HTTP_200_OK)

    def test_organization_with_admin_creation_workflow(self):
        """Test creating organization with admin through serializer workflow."""
        self.client.force_authenticate(user=self.super_admin)
        create_url = reverse('organization-create-with-admin')
        
        # Step 1: Create organization with admin
        data = {
            'name': 'Admin Creation Corp',
            'description': 'Created with admin',
            'admin_email': 'admin@creation.com',
            'admin_first_name': 'Created',
            'admin_last_name': 'Admin',
            'admin_password': 'password123'
        }
        
        response = self.client.post(create_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Step 2: Verify response structure
        self.assertIn('organization', response.data)
        self.assertIn('admin_user', response.data)
        
        org_data = response.data['organization']
        admin_data = response.data['admin_user']
        
        # Step 3: Verify organization creation
        org = Organization.objects.get(id=org_data['id'])
        self.assertEqual(org.name, 'Admin Creation Corp')
        
        # Step 4: Verify admin user creation
        admin_user = User.objects.get(id=admin_data['id'])
        self.assertEqual(admin_user.email, 'admin@creation.com')
        self.assertEqual(admin_user.organization, org)
        
        # Step 5: Verify default roles were created
        expected_roles = ['Organization Admin', 'Salesperson', 'Verifier']
        org_roles = list(org.roles.values_list('name', flat=True))
        for role_name in expected_roles:
            self.assertIn(role_name, org_roles)
        
        # Step 6: Verify admin has correct role
        org_admin_role = Role.objects.get(name='Organization Admin', organization=org)
        self.assertEqual(admin_user.role, org_admin_role)

    def test_organization_hierarchy_access_workflow(self):
        """Test organization access hierarchy workflow."""
        # Create organization with admin
        org = Organization.objects.create(name='Hierarchy Test Org')
        
        # Create roles
        admin_role = Role.objects.create(name='Admin', organization=org)
        member_role = Role.objects.create(name='Member', organization=org)
        
        # Create users
        org_admin = User.objects.create_user(
            email="orgadmin@hierarchy.com",
            password="adminpass123",
            username="orgadmin",
            organization=org,
            role=admin_role,
            is_staff=True
        )
        
        org_member = User.objects.create_user(
            email="member@hierarchy.com",
            password="memberpass123",
            username="member",
            organization=org,
            role=member_role
        )
        
        external_user = User.objects.create_user(
            email="external@other.com",
            password="externalpass123",
            username="external"
        )
        
        org_url = reverse('organizations-detail', kwargs={'pk': org.pk})
        
        # Test super admin access
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(org_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Test org admin access
        self.client.force_authenticate(user=org_admin)
        response = self.client.get(org_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Test org member access
        self.client.force_authenticate(user=org_member)
        response = self.client.get(org_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Test external user access (should be denied)
        self.client.force_authenticate(user=external_user)
        response = self.client.get(org_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_organization_list_filtering_workflow(self):
        """Test organization list filtering based on user permissions."""
        # Create multiple organizations
        org1 = Organization.objects.create(name='Organization 1')
        org2 = Organization.objects.create(name='Organization 2')
        org3 = Organization.objects.create(name='Organization 3')
        
        # Create users with different access levels
        role1 = Role.objects.create(name='Member', organization=org1)
        user1 = User.objects.create_user(
            email="user1@org1.com",
            password="pass123",
            username="user1",
            organization=org1,
            role=role1
        )
        
        role2 = Role.objects.create(name='Member', organization=org2)
        user2 = User.objects.create_user(
            email="user2@org2.com",
            password="pass123",
            username="user2",
            organization=org2,
            role=role2
        )
        
        list_url = reverse('organizations-list')
        
        # Test super admin sees all organizations
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 3)
        
        # Test user1 sees only org1
        self.client.force_authenticate(user=user1)
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], 'Organization 1')
        
        # Test user2 sees only org2
        self.client.force_authenticate(user=user2)
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], 'Organization 2')


class OrganizationCRUDWorkflowTests(APITestCase):
    """Integration tests for complete CRUD workflows."""

    def setUp(self):
        """Set up test data."""
        self.super_admin = User.objects.create_superuser(
            email="superadmin@test.com",
            password="adminpass123",
            username="superadmin"
        )

    def test_complete_crud_workflow(self):
        """Test complete CRUD workflow for organizations."""
        self.client.force_authenticate(user=self.super_admin)
        list_url = reverse('organizations-list')
        
        # CREATE: Create new organization
        create_data = {
            'name': 'CRUD Test Org',
            'description': 'Testing CRUD operations',
            'is_active': True
        }
        
        create_response = self.client.post(list_url, create_data)
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        org_id = create_response.data['id']
        
        # READ: Retrieve the created organization
        detail_url = reverse('organizations-detail', kwargs={'pk': org_id})
        read_response = self.client.get(detail_url)
        self.assertEqual(read_response.status_code, status.HTTP_200_OK)
        self.assertEqual(read_response.data['name'], 'CRUD Test Org')
        
        # UPDATE: Update the organization
        update_data = {
            'name': 'Updated CRUD Test Org',
            'description': 'Updated description',
            'is_active': False
        }
        
        update_response = self.client.put(detail_url, update_data)
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)
        self.assertEqual(update_response.data['name'], 'Updated CRUD Test Org')
        
        # PARTIAL UPDATE: Partially update the organization
        partial_data = {'description': 'Partially updated'}
        patch_response = self.client.patch(detail_url, partial_data)
        self.assertEqual(patch_response.status_code, status.HTTP_200_OK)
        self.assertEqual(patch_response.data['description'], 'Partially updated')
        self.assertEqual(patch_response.data['name'], 'Updated CRUD Test Org')  # Unchanged
        
        # DELETE: Delete the organization
        delete_response = self.client.delete(detail_url)
        self.assertEqual(delete_response.status_code, status.HTTP_204_NO_CONTENT)
        
        # Verify deletion
        verify_response = self.client.get(detail_url)
        self.assertEqual(verify_response.status_code, status.HTTP_404_NOT_FOUND)


class OrganizationErrorHandlingIntegrationTests(APITestCase):
    """Integration tests for error handling scenarios."""

    def setUp(self):
        """Set up test data."""
        self.super_admin = User.objects.create_superuser(
            email="superadmin@test.com",
            password="adminpass123",
            username="superadmin"
        )
        
        self.existing_org = Organization.objects.create(name="Existing Org")
        self.existing_user = User.objects.create_user(
            email="existing@test.com",
            password="testpass123",
            username="existing"
        )

    def test_registration_error_handling_workflow(self):
        """Test error handling in registration workflow."""
        registration_url = reverse('organization-register')
        
        # Test duplicate organization name
        duplicate_org_data = {
            'name': 'Existing Org',  # Duplicate
            'admin_first_name': 'Test',
            'admin_last_name': 'User',
            'admin_email': 'test@new.com',
            'admin_password': 'password123'
        }
        
        response = self.client.post(registration_url, duplicate_org_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('name', response.data)
        
        # Test duplicate admin email
        duplicate_email_data = {
            'name': 'New Unique Org',
            'admin_first_name': 'Test',
            'admin_last_name': 'User',
            'admin_email': 'existing@test.com',  # Duplicate
            'admin_password': 'password123'
        }
        
        response = self.client.post(registration_url, duplicate_email_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('admin_email', response.data)

    def test_crud_error_handling_workflow(self):
        """Test error handling in CRUD operations."""
        self.client.force_authenticate(user=self.super_admin)
        
        # Test creating organization with duplicate name
        list_url = reverse('organizations-list')
        duplicate_data = {'name': 'Existing Org'}
        
        response = self.client.post(list_url, duplicate_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Test accessing non-existent organization
        non_existent_url = reverse('organizations-detail', kwargs={'pk': 99999})
        response = self.client.get(non_existent_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        # Test updating non-existent organization
        update_data = {'name': 'Updated Name'}
        response = self.client.put(non_existent_url, update_data)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class OrganizationConcurrencyIntegrationTests(TransactionTestCase):
    """Integration tests for concurrency scenarios."""

    def setUp(self):
        """Set up test data."""
        self.super_admin = User.objects.create_superuser(
            email="superadmin@test.com",
            password="adminpass123",
            username="superadmin"
        )

    def test_concurrent_organization_creation(self):
        """Test concurrent organization creation scenarios."""
        # This test simulates race conditions that might occur
        # when multiple requests try to create organizations simultaneously
        
        def create_organization(name):
            try:
                org = Organization.objects.create(name=name)
                return org
            except Exception as e:
                return None
        
        # Test creating organizations with same name concurrently
        org1 = create_organization("Concurrent Org")
        org2 = create_organization("Concurrent Org")  # Should fail due to uniqueness
        
        self.assertIsNotNone(org1)
        self.assertIsNone(org2)  # Second creation should fail
        
        # Verify only one organization exists
        count = Organization.objects.filter(name="Concurrent Org").count()
        self.assertEqual(count, 1)

    def test_organization_with_admin_atomic_creation(self):
        """Test atomic creation of organization with admin."""
        # Simulate failure scenario to test rollback
        data = {
            'name': 'Atomic Test Org',
            'description': 'Testing atomic creation',
            'admin_email': 'admin@atomic.com',
            'admin_first_name': 'Atomic',
            'admin_last_name': 'Test',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationWithAdminSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        # Normal creation should work
        result = serializer.save()
        
        # Verify both organization and user were created
        org = result['organization']
        admin_user = result['admin_user']
        
        self.assertTrue(Organization.objects.filter(id=org.id).exists())
        self.assertTrue(User.objects.filter(id=admin_user.id).exists())
        
        # Verify roles were created
        role_count = Role.objects.filter(organization=org).count()
        self.assertEqual(role_count, 3)  # Organization Admin, Salesperson, Verifier


class OrganizationCrossPlatformIntegrationTests(APITestCase):
    """Integration tests for cross-platform compatibility."""

    def setUp(self):
        """Set up test data."""
        self.super_admin = User.objects.create_superuser(
            email="superadmin@test.com",
            password="adminpass123",
            username="superadmin"
        )

    def test_organizations_alias_endpoint_compatibility(self):
        """Test the organizations alias endpoint for frontend compatibility."""
        self.client.force_authenticate(user=self.super_admin)
        alias_url = reverse('organizations-alias')
        
        # Test GET request (should list organizations)
        response = self.client.get(alias_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, list)
        
        # Test POST with simple organization
        simple_data = {
            'name': 'Simple Frontend Org',
            'description': 'Created via alias endpoint',
            'is_active': True
        }
        
        response = self.client.post(alias_url, simple_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Test POST with admin data (should use different creation flow)
        admin_data = {
            'name': 'Frontend Org With Admin',
            'admin_email': 'admin@frontend.com',
            'admin_first_name': 'Frontend',
            'admin_last_name': 'Admin',
            'admin_password': 'password123'
        }
        
        response = self.client.post(alias_url, admin_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('organization', response.data)
        self.assertIn('admin_user', response.data)

    def test_api_response_format_consistency(self):
        """Test that API responses maintain consistent format."""
        self.client.force_authenticate(user=self.super_admin)
        
        # Create organization
        org = Organization.objects.create(
            name="Format Test Org",
            description="Testing response format"
        )
        
        # Test list endpoint format
        list_url = reverse('organizations-list')
        list_response = self.client.get(list_url)
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        
        # Verify list response structure
        self.assertIsInstance(list_response.data, list)
        if list_response.data:
            org_data = list_response.data[0]
            required_fields = ['id', 'name', 'description', 'is_active', 'created_at']
            for field in required_fields:
                self.assertIn(field, org_data)
        
        # Test detail endpoint format
        detail_url = reverse('organizations-detail', kwargs={'pk': org.pk})
        detail_response = self.client.get(detail_url)
        self.assertEqual(detail_response.status_code, status.HTTP_200_OK)
        
        # Verify detail response structure
        org_data = detail_response.data
        required_fields = ['id', 'name', 'description', 'is_active', 'created_at', 'user_count', 'role_count']
        for field in required_fields:
            self.assertIn(field, org_data) 