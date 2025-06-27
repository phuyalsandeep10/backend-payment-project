from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from decimal import Decimal

from authentication.models import User
from organization.models import Organization
from .models import Commission

class CommissionAPITests(APITestCase):
    """
    Test suite for the Commission API endpoints.
    """

    def setUp(self):
        # Create two separate organizations
        self.org1 = Organization.objects.create(name="Org One")
        self.org2 = Organization.objects.create(name="Org Two")

        # Create an admin for Org One
        self.org1_admin = User.objects.create_user(
            username="org1_admin",
            password="password123",
            role=User.Role.ORG_ADMIN,
            organization=self.org1
        )

        # Create a regular user in Org One
        self.org1_user = User.objects.create_user(
            username="org1_user",
            password="password123",
            role=User.Role.USER,
            organization=self.org1
        )
        
        # Create an admin for Org Two to test data isolation
        self.org2_admin = User.objects.create_user(
            username="org2_admin",
            password="password123",
            role=User.Role.ORG_ADMIN,
            organization=self.org2
        )

        # Create a commission record for the user in Org One
        self.commission1 = Commission.objects.create(
            user=self.org1_user,
            organization=self.org1,
            total_sales=Decimal('10000.00'),
            commission_percentage=Decimal('5.00'),
            start_date="2025-01-01",
            end_date="2025-01-31"
        )

    def test_unauthenticated_access_denied(self):
        """
        Ensure unauthenticated users cannot access any commission endpoints.
        """
        url = reverse('commission-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_org_admin_can_list_their_commissions(self):
        """
        Ensure an Org Admin can list commissions ONLY from their own organization.
        """
        # Authenticate as the admin of Org One
        self.client.force_authenticate(user=self.org1_admin)
        
        url = reverse('commission-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only see the 1 commission from their org
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['id'], self.commission1.id)

    def test_org_admin_cannot_see_other_org_commissions(self):
        """
        CRITICAL: Ensure an admin from one org cannot access another org's data.
        """
        # Authenticate as the admin of Org Two
        self.client.force_authenticate(user=self.org2_admin)
        
        url = reverse('commission-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should see ZERO commissions, as they have none in their org
        self.assertEqual(len(response.data), 0)

    def test_commission_calculation_on_save(self):
        """
        Test that the model's internal calculation logic is correct.
        """
        # Values from the setUp commission record.
        # It was saved once during setUp, so calculation has already run.
        commission = self.commission1
        self.assertEqual(commission.converted_amount, Decimal('500.00')) # 10000 * 5%

        # Update the record and check recalculation
        commission.total_sales = Decimal('20000.00')
        commission.save()
        
        # Refresh from DB and check again
        commission.refresh_from_db()
        self.assertEqual(commission.converted_amount, Decimal('1000.00')) # 20000 * 5%

    def test_create_commission_record(self):
        """
        Ensure an Org Admin can create a new commission record.
        """
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('commission-list')
        data = {
            "user": self.org1_user.id,
            "total_sales": "30000.00",
            "start_date": "2025-02-01",
            "end_date": "2025-02-28"
        }
        
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify the backend calculation. Default percentage is 5%.
        # 30000 * 5% = 1500
        self.assertEqual(Decimal(response.data['converted_amount']), Decimal('1500.00'))
        self.assertEqual(response.data['user'], self.org1_user.id)
