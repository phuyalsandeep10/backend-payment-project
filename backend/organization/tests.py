from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from decimal import Decimal

from authentication.models import User
from organization.models import Organization
from commission.models import Commission

# Create your tests here.

class EndToEndWorkflowTests(APITestCase):
    """
    Tests the complete end-to-end user workflow from Super Admin to Org Admin.
    """

    def setUp(self):
        # 1. Create a Super Admin
        self.super_admin = User.objects.create_superuser(
            username="super_admin",
            password="super_password",
            email="super@admin.com",
            role=User.Role.SUPER_ADMIN
        )
        self.client.force_authenticate(user=self.super_admin)

    def test_super_admin_to_commission_creation_workflow(self):
        """
        Test the full flow:
        - Super Admin creates an Org and an Org Admin.
        - Org Admin logs in.
        - Org Admin creates a commission record for a user in their org.
        """
        # 2. Super Admin creates a new Organization
        org_url = reverse('organization-list')
        org_data = {"name": "TestCorp", "is_active": True}
        response = self.client.post(org_url, org_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_org_id = response.data['id']
        self.assertEqual(Organization.objects.count(), 1)

        # 3. Super Admin creates an Org Admin for that Organization
        admin_url = reverse('org-admin-list')
        admin_data = {
            "username": "test_org_admin",
            "email": "org_admin@testcorp.com",
            "organization": new_org_id,
            "password": "org_admin_password",
            "password_confirm": "org_admin_password"
        }
        response = self.client.post(admin_url, admin_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        org_admin_user = User.objects.get(username="test_org_admin")

        # As a necessary prerequisite, create a regular user in the new org
        # In a real app, the Org Admin would do this via another endpoint.
        regular_user = User.objects.create_user(
            username="regular_employee",
            password="password123",
            organization_id=new_org_id,
            role=User.Role.USER
        )

        # 4. The new Org Admin logs in
        self.client.logout()
        self.client.force_authenticate(user=org_admin_user)

        # 5. The Org Admin creates a commission record for their user
        commission_url = reverse('commission-list')
        commission_data = {
            "user": regular_user.id,
            "total_sales": "50000.00",
            "start_date": "2025-03-01",
            "end_date": "2025-03-31"
        }
        response = self.client.post(commission_url, commission_data)

        # 6. Assert the results
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Commission.objects.count(), 1)
        
        # Check that the commission was created for the correct user and org
        new_commission = Commission.objects.first()
        self.assertEqual(new_commission.user, regular_user)
        self.assertEqual(new_commission.organization.id, new_org_id)
        
        # Verify backend calculation (with default commission %)
        # 50000 * 5% = 2500
        self.assertEqual(new_commission.converted_amount, Decimal('2500.00'))
