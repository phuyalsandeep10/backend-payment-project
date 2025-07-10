from django.test import TestCase
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from decimal import Decimal
from faker import Faker
from organization.models import Organization
from authentication.models import User
from permissions.models import Role

fake = Faker()

class OrganizationModelTests(TestCase):
    """Comprehensive tests for the Organization model."""

    def setUp(self):
        """Set up test data."""
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="A test organization for unit testing"
        )
        
        # Create a user to test created_by relationship
        self.user = User.objects.create_user(
            email="creator@test.com",
            password="testpass123",
            username="creator"
        )

    def test_organization_creation(self):
        """Test basic organization creation."""
        org = Organization.objects.create(
            name="New Test Org",
            description="Test description"
        )
        self.assertEqual(org.name, "New Test Org")
        self.assertEqual(org.description, "Test description")
        self.assertTrue(org.is_active)
        self.assertEqual(org.sales_goal, Decimal('100000.00'))
        self.assertIsNone(org.created_by)
        self.assertIsNotNone(org.created_at)
        self.assertIsNotNone(org.updated_at)

    def test_organization_creation_with_creator(self):
        """Test organization creation with a creator."""
        org = Organization.objects.create(
            name="Creator Test Org",
            description="Test with creator",
            created_by=self.user
        )
        self.assertEqual(org.created_by, self.user)
        self.assertEqual(org.name, "Creator Test Org")

    def test_organization_str_method(self):
        """Test the __str__ method returns the organization name."""
        self.assertEqual(str(self.organization), "Test Organization")

    def test_organization_name_uniqueness(self):
        """Test that organization names must be unique."""
        with self.assertRaises(IntegrityError):
            Organization.objects.create(name="Test Organization")

    def test_organization_name_max_length(self):
        """Test organization name maximum length constraint."""
        long_name = "x" * 256  # 256 characters, exceeds max_length=255
        org = Organization(name=long_name)
        with self.assertRaises(ValidationError):
            org.full_clean()

    def test_organization_description_can_be_blank(self):
        """Test that description can be blank or null."""
        org1 = Organization.objects.create(name="Blank Desc Org", description="")
        org2 = Organization.objects.create(name="Null Desc Org", description=None)
        
        self.assertEqual(org1.description, "")
        self.assertIsNone(org2.description)

    def test_organization_default_values(self):
        """Test default values are set correctly."""
        org = Organization.objects.create(name="Default Values Org")
        self.assertTrue(org.is_active)
        self.assertEqual(org.sales_goal, Decimal('100000.00'))
        self.assertIsNone(org.created_by)

    def test_organization_custom_values(self):
        """Test setting custom values."""
        org = Organization.objects.create(
            name="Custom Values Org",
            description="Custom description",
            is_active=False,
            sales_goal=Decimal('250000.50'),
            created_by=self.user
        )
        self.assertEqual(org.description, "Custom description")
        self.assertFalse(org.is_active)
        self.assertEqual(org.sales_goal, Decimal('250000.50'))
        self.assertEqual(org.created_by, self.user)

    def test_sales_goal_decimal_precision(self):
        """Test sales_goal decimal field precision and scale."""
        # Test maximum precision (15 digits, 2 decimal places)
        max_value = Decimal('9999999999999.99')  # 13 digits before decimal + 2 after
        org = Organization.objects.create(
            name="Max Sales Goal Org",
            sales_goal=max_value
        )
        self.assertEqual(org.sales_goal, max_value)

    def test_sales_goal_negative_value(self):
        """Test that negative sales goals are allowed (business decision)."""
        org = Organization.objects.create(
            name="Negative Sales Goal Org",
            sales_goal=Decimal('-1000.00')
        )
        self.assertEqual(org.sales_goal, Decimal('-1000.00'))

    def test_organization_ordering(self):
        """Test that organizations are ordered by created_at descending."""
        # Create multiple organizations
        org1 = Organization.objects.create(name="First Org")
        org2 = Organization.objects.create(name="Second Org") 
        org3 = Organization.objects.create(name="Third Org")
        
        # Get all organizations
        orgs = list(Organization.objects.all())
        
        # Should be ordered by most recent first
        self.assertEqual(orgs[0], org3)  # Most recent
        self.assertEqual(orgs[1], org2)  # Middle
        self.assertEqual(orgs[2], org1)  # Oldest
        # Include the one from setUp
        self.assertEqual(orgs[3], self.organization)

    def test_organization_meta_options(self):
        """Test model meta options."""
        meta = Organization._meta
        self.assertEqual(meta.ordering, ['-created_at'])
        self.assertEqual(meta.verbose_name, 'Organization')
        self.assertEqual(meta.verbose_name_plural, 'Organizations')

    def test_created_by_set_null_on_delete(self):
        """Test that created_by is set to null when the user is deleted."""
        org = Organization.objects.create(
            name="User Delete Test Org",
            created_by=self.user
        )
        
        # Verify the relationship exists
        self.assertEqual(org.created_by, self.user)
        
        # Delete the user
        user_id = self.user.id
        self.user.delete()
        
        # Refresh the organization and check created_by is now null
        org.refresh_from_db()
        self.assertIsNone(org.created_by)

    def test_organization_with_empty_name(self):
        """Test that empty name raises validation error."""
        org = Organization(name="", description="Test")
        with self.assertRaises(ValidationError):
            org.full_clean()

    def test_organization_relationships(self):
        """Test related fields work correctly."""
        # Test that users can have organizations
        user_with_org = User.objects.create_user(
            email="user@org.com",
            password="testpass123",
            username="userorg",
            organization=self.organization
        )
        
        self.assertEqual(user_with_org.organization, self.organization)
        
        # Test that roles can have organizations  
        role = Role.objects.create(
            name="Test Role",
            organization=self.organization
        )
        
        self.assertEqual(role.organization, self.organization)

    def test_organization_bulk_operations(self):
        """Test bulk operations work correctly."""
        # Bulk create
        orgs = Organization.objects.bulk_create([
            Organization(name=f"Bulk Org {i}") for i in range(3)
        ])
        
        self.assertEqual(len(orgs), 3)
        self.assertEqual(Organization.objects.filter(name__startswith="Bulk Org").count(), 3)
        
        # Bulk update
        Organization.objects.filter(name__startswith="Bulk Org").update(is_active=False)
        
        inactive_count = Organization.objects.filter(
            name__startswith="Bulk Org", 
            is_active=False
        ).count()
        self.assertEqual(inactive_count, 3)

    def test_organization_case_sensitive_names(self):
        """Test that organization names are case sensitive."""
        org1 = Organization.objects.create(name="Test Case")
        org2 = Organization.objects.create(name="test case")  # Different case
        
        self.assertNotEqual(org1.name, org2.name)
        self.assertEqual(Organization.objects.filter(name__iexact="test case").count(), 2) 