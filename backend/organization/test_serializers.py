from django.test import TestCase
from rest_framework.exceptions import ValidationError
from faker import Faker
from organization.models import Organization
from organization.serializers import (
    OrganizationSerializer, 
    OrganizationRegistrationSerializer,
    OrganizationWithAdminSerializer
)
from authentication.models import User
from permissions.models import Role

fake = Faker()

class OrganizationSerializerTests(TestCase):
    """Comprehensive tests for OrganizationSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email="creator@test.com",
            password="testpass123",
            username="creator"
        )
        
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test description",
            created_by=self.user
        )

    def test_organization_serialization(self):
        """Test basic organization serialization."""
        serializer = OrganizationSerializer(self.organization)
        data = serializer.data
        
        self.assertEqual(data['name'], "Test Organization")
        self.assertEqual(data['description'], "Test description")
        self.assertTrue(data['is_active'])
        self.assertEqual(data['created_by'], self.user.id)
        self.assertEqual(data['created_by_username'], self.user.username)
        self.assertIn('created_at', data)
        self.assertIn('id', data)

    def test_organization_serialization_without_creator(self):
        """Test serialization of organization without creator."""
        org = Organization.objects.create(name="No Creator Org")
        serializer = OrganizationSerializer(org)
        data = serializer.data
        
        self.assertIsNone(data['created_by'])
        self.assertIsNone(data.get('created_by_username'))

    def test_organization_deserialization_create(self):
        """Test creating organization through serializer."""
        data = {
            'name': 'New Serialized Org',
            'description': 'Created via serializer',
            'is_active': True
        }
        
        serializer = OrganizationSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        org = serializer.save()
        self.assertEqual(org.name, 'New Serialized Org')
        self.assertEqual(org.description, 'Created via serializer')
        self.assertTrue(org.is_active)

    def test_organization_deserialization_update(self):
        """Test updating organization through serializer."""
        data = {
            'name': 'Updated Organization Name',
            'description': 'Updated description',
            'is_active': False
        }
        
        serializer = OrganizationSerializer(self.organization, data=data)
        self.assertTrue(serializer.is_valid())
        
        updated_org = serializer.save()
        self.assertEqual(updated_org.name, 'Updated Organization Name')
        self.assertEqual(updated_org.description, 'Updated description')
        self.assertFalse(updated_org.is_active)

    def test_organization_serializer_validation_empty_name(self):
        """Test validation fails for empty name."""
        data = {'name': '', 'description': 'Test'}
        serializer = OrganizationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('name', serializer.errors)

    def test_organization_serializer_read_only_fields(self):
        """Test that read-only fields are not updated."""
        # Try to update read-only fields
        data = {
            'name': 'Updated Name',
            'created_by': 999,  # Should be ignored
            'created_by_username': 'ignored',  # Should be ignored
            'user_count': 999,  # Should be ignored
            'role_count': 999  # Should be ignored
        }
        
        serializer = OrganizationSerializer(self.organization, data=data, partial=True)
        self.assertTrue(serializer.is_valid())
        
        updated_org = serializer.save()
        self.assertEqual(updated_org.name, 'Updated Name')
        self.assertEqual(updated_org.created_by, self.user)  # Unchanged


class OrganizationRegistrationSerializerTests(TestCase):
    """Comprehensive tests for OrganizationRegistrationSerializer."""

    def setUp(self):
        """Set up test data."""
        # Create existing organization and user for uniqueness tests
        self.existing_org = Organization.objects.create(name="Existing Org")
        self.existing_user = User.objects.create_user(
            email="existing@test.com",
            password="testpass123",
            username="existing"
        )

    def test_valid_registration_data(self):
        """Test serializer with valid registration data."""
        data = {
            'name': 'New Company',
            'description': 'A new company description',
            'admin_first_name': 'John',
            'admin_last_name': 'Doe',
            'admin_email': 'john.doe@newcompany.com',
            'admin_password': 'securepassword123'
        }
        
        serializer = OrganizationRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['name'], 'New Company')
        self.assertEqual(serializer.validated_data['admin_email'], 'john.doe@newcompany.com')

    def test_registration_without_description(self):
        """Test registration without description (optional field)."""
        data = {
            'name': 'Company Without Desc',
            'admin_first_name': 'Jane',
            'admin_last_name': 'Smith',
            'admin_email': 'jane@company.com',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_registration_with_blank_description(self):
        """Test registration with blank description."""
        data = {
            'name': 'Company Blank Desc',
            'description': '',
            'admin_first_name': 'Bob',
            'admin_last_name': 'Johnson',
            'admin_email': 'bob@company.com',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_duplicate_organization_name_validation(self):
        """Test validation fails for duplicate organization name."""
        data = {
            'name': 'Existing Org',  # Same as existing organization
            'admin_first_name': 'Test',
            'admin_last_name': 'User',
            'admin_email': 'test@test.com',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('name', serializer.errors)
        self.assertIn('already exists', str(serializer.errors['name'][0]))

    def test_duplicate_organization_name_case_insensitive(self):
        """Test validation fails for duplicate organization name (case insensitive)."""
        data = {
            'name': 'existing org',  # Different case but same name
            'admin_first_name': 'Test',
            'admin_last_name': 'User',
            'admin_email': 'test@test.com',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('name', serializer.errors)

    def test_duplicate_admin_email_validation(self):
        """Test validation fails for duplicate admin email."""
        data = {
            'name': 'New Unique Org',
            'admin_first_name': 'Test',
            'admin_last_name': 'User',
            'admin_email': 'existing@test.com',  # Same as existing user
            'admin_password': 'password123'
        }
        
        serializer = OrganizationRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('admin_email', serializer.errors)
        self.assertIn('already exists', str(serializer.errors['admin_email'][0]))

    def test_duplicate_admin_email_case_insensitive(self):
        """Test validation fails for duplicate admin email (case insensitive)."""
        data = {
            'name': 'New Unique Org',
            'admin_first_name': 'Test',
            'admin_last_name': 'User',
            'admin_email': 'EXISTING@TEST.COM',  # Different case but same email
            'admin_password': 'password123'
        }
        
        serializer = OrganizationRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('admin_email', serializer.errors)

    def test_missing_required_fields(self):
        """Test validation fails when required fields are missing."""
        incomplete_data = {
            'name': 'Incomplete Org'
            # Missing admin fields
        }
        
        serializer = OrganizationRegistrationSerializer(data=incomplete_data)
        self.assertFalse(serializer.is_valid())
        
        required_fields = ['admin_first_name', 'admin_last_name', 'admin_email', 'admin_password']
        for field in required_fields:
            self.assertIn(field, serializer.errors)

    def test_invalid_email_format(self):
        """Test validation fails for invalid email format."""
        data = {
            'name': 'Test Org',
            'admin_first_name': 'Test',
            'admin_last_name': 'User',
            'admin_email': 'invalid-email-format',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('admin_email', serializer.errors)


class OrganizationWithAdminSerializerTests(TestCase):
    """Comprehensive tests for OrganizationWithAdminSerializer."""

    def setUp(self):
        """Set up test data."""
        self.existing_user = User.objects.create_user(
            email="existing@test.com",
            password="testpass123",
            username="existing"
        )

    def test_valid_organization_with_admin_data(self):
        """Test serializer with valid data."""
        data = {
            'name': 'Test Company',
            'description': 'A test company',
            'admin_email': 'admin@testcompany.com',
            'admin_first_name': 'Admin',
            'admin_last_name': 'User',
            'admin_password': 'securepassword123'
        }
        
        serializer = OrganizationWithAdminSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_create_organization_with_admin(self):
        """Test creating organization with admin through serializer."""
        data = {
            'name': 'Created Company',
            'description': 'Created via serializer',
            'admin_email': 'admin@created.com',
            'admin_first_name': 'Created',
            'admin_last_name': 'Admin',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationWithAdminSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        result = serializer.save()
        
        # Check organization was created
        org = result['organization']
        self.assertEqual(org.name, 'Created Company')
        self.assertEqual(org.description, 'Created via serializer')
        
        # Check admin user was created
        admin_user = result['admin_user']
        self.assertEqual(admin_user.email, 'admin@created.com')
        self.assertEqual(admin_user.first_name, 'Created')
        self.assertEqual(admin_user.last_name, 'Admin')
        self.assertEqual(admin_user.organization, org)
        self.assertTrue(admin_user.is_active)
        
        # Check admin has the correct role
        self.assertEqual(admin_user.role.name, 'Organization Admin')
        self.assertEqual(admin_user.role.organization, org)

    def test_create_organization_without_description(self):
        """Test creating organization without description."""
        data = {
            'name': 'No Desc Company',
            'admin_email': 'admin@nodesc.com',
            'admin_first_name': 'No',
            'admin_last_name': 'Desc',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationWithAdminSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        result = serializer.save()
        org = result['organization']
        self.assertEqual(org.description, '')

    def test_create_organization_with_blank_description(self):
        """Test creating organization with blank description."""
        data = {
            'name': 'Blank Desc Company',
            'description': '',
            'admin_email': 'admin@blank.com',
            'admin_first_name': 'Blank',
            'admin_last_name': 'Desc',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationWithAdminSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        result = serializer.save()
        org = result['organization']
        self.assertEqual(org.description, '')

    def test_duplicate_admin_email_validation(self):
        """Test validation fails for duplicate admin email."""
        data = {
            'name': 'Duplicate Email Org',
            'admin_email': 'existing@test.com',  # Same as existing user
            'admin_first_name': 'Duplicate',
            'admin_last_name': 'Email',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationWithAdminSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('admin_email', serializer.errors)
        self.assertIn('already exists', str(serializer.errors['admin_email'][0]))

    def test_missing_required_fields(self):
        """Test validation fails when required fields are missing."""
        incomplete_data = {
            'name': 'Incomplete Org'
            # Missing admin fields
        }
        
        serializer = OrganizationWithAdminSerializer(data=incomplete_data)
        self.assertFalse(serializer.is_valid())
        
        required_fields = ['admin_email', 'admin_first_name', 'admin_last_name', 'admin_password']
        for field in required_fields:
            self.assertIn(field, serializer.errors)

    def test_invalid_email_format(self):
        """Test validation fails for invalid email format."""
        data = {
            'name': 'Invalid Email Org',
            'admin_email': 'not-an-email',
            'admin_first_name': 'Invalid',
            'admin_last_name': 'Email',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationWithAdminSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('admin_email', serializer.errors)

    def test_default_roles_created(self):
        """Test that default roles are created for the organization."""
        data = {
            'name': 'Roles Test Company',
            'admin_email': 'admin@roles.com',
            'admin_first_name': 'Roles',
            'admin_last_name': 'Test',
            'admin_password': 'password123'
        }
        
        serializer = OrganizationWithAdminSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        result = serializer.save()
        org = result['organization']
        
        # Check default roles were created
        role_names = list(org.roles.values_list('name', flat=True))
        expected_roles = ['Organization Admin', 'Salesperson', 'Verifier']
        
        for role_name in expected_roles:
            self.assertIn(role_name, role_names)

    def test_admin_password_is_write_only(self):
        """Test that admin_password is write-only and not in serialized data."""
        data = {
            'name': 'Password Test Company',
            'admin_email': 'admin@password.com',
            'admin_first_name': 'Password',
            'admin_last_name': 'Test',
            'admin_password': 'secretpassword123'
        }
        
        serializer = OrganizationWithAdminSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        # Check that admin_password is not exposed in validated_data for serialization
        # This serializer is input-only for creating, not for output serialization
        validated_data = serializer.validated_data
        self.assertIn('admin_password', validated_data)  # It should be in validated_data for creation
        
        # Verify the password field is marked as write_only in the serializer
        admin_password_field = serializer.fields['admin_password']
        self.assertTrue(admin_password_field.write_only) 