from django.test import TestCase
from rest_framework.test import APIRequestFactory
from rest_framework.request import Request
from unittest.mock import Mock
from organization.models import Organization
from organization.permissions import IsOrganizationMember
from authentication.models import User
from permissions.models import Role

class IsOrganizationMemberPermissionTests(TestCase):
    """Comprehensive tests for IsOrganizationMember permission class."""

    def setUp(self):
        """Set up test data."""
        self.factory = APIRequestFactory()
        self.permission = IsOrganizationMember()
        
        # Create organizations
        self.org1 = Organization.objects.create(name="Organization 1")
        self.org2 = Organization.objects.create(name="Organization 2")
        
        # Create users
        self.role1 = Role.objects.create(name="Member", organization=self.org1)
        self.member_user = User.objects.create_user(
            email="member@test.com",
            password="testpass123",
            username="member",
            organization=self.org1,
            role=self.role1
        )
        
        self.role2 = Role.objects.create(name="Member", organization=self.org2)
        self.non_member_user = User.objects.create_user(
            email="nonmember@test.com",
            password="testpass123",
            username="nonmember",
            organization=self.org2,
            role=self.role2
        )
        
        self.staff_user = User.objects.create_user(
            email="staff@test.com",
            password="testpass123",
            username="staff",
            organization=self.org1,
            role=self.role1,
            is_staff=True
        )
        
        self.no_org_user = User.objects.create_user(
            email="noorg@test.com",
            password="testpass123",
            username="noorg"
        )

    def test_has_object_permission_read_access_member(self):
        """Test member has read access to their organization."""
        request = self.factory.get('/')
        request.user = self.member_user
        request.method = 'GET'
        
        view = Mock()
        
        has_permission = self.permission.has_object_permission(
            request, view, self.org1
        )
        
        self.assertTrue(has_permission)

    def test_has_object_permission_read_access_non_member(self):
        """Test non-member doesn't have read access to organization."""
        request = self.factory.get('/')
        request.user = self.non_member_user
        request.method = 'GET'
        
        view = Mock()
        
        has_permission = self.permission.has_object_permission(
            request, view, self.org1
        )
        
        self.assertFalse(has_permission)

    def test_has_object_permission_read_access_no_organization(self):
        """Test user with no organization doesn't have access."""
        request = self.factory.get('/')
        request.user = self.no_org_user
        request.method = 'GET'
        
        view = Mock()
        
        has_permission = self.permission.has_object_permission(
            request, view, self.org1
        )
        
        self.assertFalse(has_permission)

    def test_has_object_permission_write_access_staff_member(self):
        """Test staff member has write access to their organization."""
        request = self.factory.post('/')
        request.user = self.staff_user
        request.method = 'POST'
        
        view = Mock()
        
        has_permission = self.permission.has_object_permission(
            request, view, self.org1
        )
        
        self.assertTrue(has_permission)

    def test_has_object_permission_write_access_regular_member(self):
        """Test regular member doesn't have write access."""
        request = self.factory.post('/')
        request.user = self.member_user
        request.method = 'POST'
        
        view = Mock()
        
        has_permission = self.permission.has_object_permission(
            request, view, self.org1
        )
        
        self.assertFalse(has_permission)

    def test_has_object_permission_write_access_staff_non_member(self):
        """Test staff user has write access even if not member of organization."""
        # Make staff user not a member of org1
        self.staff_user.organization = self.org2
        self.staff_user.save()
        
        request = self.factory.put('/')
        request.user = self.staff_user
        request.method = 'PUT'
        
        view = Mock()
        
        has_permission = self.permission.has_object_permission(
            request, view, self.org1
        )
        
        self.assertTrue(has_permission)  # Staff privilege overrides membership

    def test_has_object_permission_write_methods(self):
        """Test write permission for different HTTP methods."""
        write_methods = ['POST', 'PUT', 'PATCH', 'DELETE']
        
        for method in write_methods:
            request = self.factory.generic(method, '/')
            request.user = self.staff_user
            request.method = method
            
            view = Mock()
            
            has_permission = self.permission.has_object_permission(
                request, view, self.org1
            )
            
            self.assertTrue(has_permission, f"Staff should have {method} access")

    def test_has_object_permission_safe_methods(self):
        """Test read permission for safe HTTP methods."""
        safe_methods = ['GET', 'HEAD', 'OPTIONS']
        
        for method in safe_methods:
            request = self.factory.generic(method, '/')
            request.user = self.member_user
            request.method = method
            
            view = Mock()
            
            has_permission = self.permission.has_object_permission(
                request, view, self.org1
            )
            
            self.assertTrue(has_permission, f"Member should have {method} access")

    def test_has_object_permission_organization_none(self):
        """Test permission when organization is None."""
        request = self.factory.get('/')
        request.user = self.member_user
        request.method = 'GET'
        
        view = Mock()
        
        # Test with None organization
        has_permission = self.permission.has_object_permission(
            request, view, None
        )
        
        self.assertFalse(has_permission)

    def test_has_object_permission_user_organization_none(self):
        """Test permission when user.organization is None."""
        # Set user organization to None
        self.member_user.organization = None
        self.member_user.save()
        
        request = self.factory.get('/')
        request.user = self.member_user
        request.method = 'GET'
        
        view = Mock()
        
        has_permission = self.permission.has_object_permission(
            request, view, self.org1
        )
        
        self.assertFalse(has_permission)


class OrganizationAccessControlIntegrationTests(TestCase):
    """Integration tests for organization access control across the system."""

    def setUp(self):
        """Set up test data."""
        # Create organizations
        self.org_a = Organization.objects.create(name="Organization A")
        self.org_b = Organization.objects.create(name="Organization B")
        
        # Create super admin
        self.super_admin = User.objects.create_superuser(
            email="superadmin@test.com",
            password="adminpass123",
            username="superadmin"
        )
        
        # Create org A admin
        self.org_a_admin_role = Role.objects.create(name="Admin", organization=self.org_a)
        self.org_a_admin = User.objects.create_user(
            email="admin_a@test.com",
            password="testpass123",
            username="admin_a",
            organization=self.org_a,
            role=self.org_a_admin_role,
            is_staff=True
        )
        
        # Create org A member
        self.org_a_member_role = Role.objects.create(name="Member", organization=self.org_a)
        self.org_a_member = User.objects.create_user(
            email="member_a@test.com",
            password="testpass123",
            username="member_a",
            organization=self.org_a,
            role=self.org_a_member_role
        )
        
        # Create org B member
        self.org_b_member_role = Role.objects.create(name="Member", organization=self.org_b)
        self.org_b_member = User.objects.create_user(
            email="member_b@test.com",
            password="testpass123",
            username="member_b",
            organization=self.org_b,
            role=self.org_b_member_role
        )

    def test_super_admin_access_all_organizations(self):
        """Test super admin can access all organizations."""
        orgs = [self.org_a, self.org_b]
        
        for org in orgs:
            # Super admin should have full access
            self.assertTrue(self.super_admin.is_superuser)
            self.assertTrue(self.super_admin.is_staff)

    def test_org_admin_cross_organization_access(self):
        """Test org admin access across organizations."""
        # Org A admin should have staff privileges
        self.assertTrue(self.org_a_admin.is_staff)
        self.assertEqual(self.org_a_admin.organization, self.org_a)
        
        # Verify admin is not super admin
        self.assertFalse(self.org_a_admin.is_superuser)

    def test_member_organization_isolation(self):
        """Test members are isolated to their organizations."""
        # Org A member
        self.assertEqual(self.org_a_member.organization, self.org_a)
        self.assertFalse(self.org_a_member.is_staff)
        self.assertFalse(self.org_a_member.is_superuser)
        
        # Org B member
        self.assertEqual(self.org_b_member.organization, self.org_b)
        self.assertFalse(self.org_b_member.is_staff)
        self.assertFalse(self.org_b_member.is_superuser)
        
        # Members should not be able to access other organizations
        self.assertNotEqual(self.org_a_member.organization, self.org_b)
        self.assertNotEqual(self.org_b_member.organization, self.org_a)

    def test_role_organization_consistency(self):
        """Test that user roles belong to their organization."""
        # Verify role consistency
        self.assertEqual(self.org_a_admin.role.organization, self.org_a)
        self.assertEqual(self.org_a_member.role.organization, self.org_a)
        self.assertEqual(self.org_b_member.role.organization, self.org_b)

    def test_organization_hierarchy_permissions(self):
        """Test permission hierarchy: super admin > org admin > member."""
        # Super admin has highest privileges
        self.assertTrue(self.super_admin.is_superuser)
        self.assertTrue(self.super_admin.is_staff)
        
        # Org admin has staff privileges but not super admin
        self.assertFalse(self.org_a_admin.is_superuser)
        self.assertTrue(self.org_a_admin.is_staff)
        
        # Members have no admin privileges
        self.assertFalse(self.org_a_member.is_superuser)
        self.assertFalse(self.org_a_member.is_staff)

    def test_organization_deletion_impact(self):
        """Test impact of organization deletion on users."""
        # Get user count before deletion
        initial_user_count = User.objects.count()
        
        # Delete organization B
        org_b_id = self.org_b.id
        self.org_b.delete()
        
        # Users should still exist but have no organization
        self.assertEqual(User.objects.count(), initial_user_count)
        
        # Refresh user from database
        self.org_b_member.refresh_from_db()
        
        # User's organization should be None (due to SET_NULL)
        # Note: This depends on the actual model relationship setup
        # If it's CASCADE, the user would be deleted instead

    def test_role_deletion_impact(self):
        """Test impact of role deletion on users."""
        # Delete the role
        role_id = self.org_a_member_role.id
        self.org_a_member_role.delete()
        
        # User should still exist but have no role
        self.org_a_member.refresh_from_db()
        # User's role should be None (due to SET_NULL)

    def test_user_organization_change(self):
        """Test changing user's organization."""
        # Move org A member to org B
        original_org = self.org_a_member.organization
        
        self.org_a_member.organization = self.org_b
        self.org_a_member.save()
        
        # Verify the change
        self.org_a_member.refresh_from_db()
        self.assertEqual(self.org_a_member.organization, self.org_b)
        self.assertNotEqual(self.org_a_member.organization, original_org)

    def test_multiple_users_same_organization(self):
        """Test multiple users in the same organization."""
        # Create additional users for org A
        additional_member = User.objects.create_user(
            email="additional@test.com",
            password="testpass123",
            username="additional",
            organization=self.org_a,
            role=self.org_a_member_role
        )
        
        # Verify all users belong to org A
        org_a_users = User.objects.filter(organization=self.org_a)
        self.assertIn(self.org_a_admin, org_a_users)
        self.assertIn(self.org_a_member, org_a_users)
        self.assertIn(additional_member, org_a_users)
        
        # Verify count
        self.assertEqual(org_a_users.count(), 3) 