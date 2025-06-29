from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from decimal import Decimal

from authentication.models import User
from organization.models import Organization
from permissions.models import Role
from .models import Commission

class CommissionAPITests(APITestCase):
    """
    Test suite for the Commission API endpoints.
    """

    def setUp(self):
        # Orgs
        self.org1 = Organization.objects.create(name='Org 1')
        self.org2 = Organization.objects.create(name='Org 2')

        # Super Admin
        self.super_admin_role = Role.objects.create(name='Super Admin')
        self.super_admin = User.objects.create_user(
            email='super@test.com',
            username='superadmin',
            password='password123',
            role=self.super_admin_role,
            is_superuser=True
        )

        # Org 1 Admin and User
        self.org1_admin_role = Role.objects.create(name='Org Admin', organization=self.org1)
        self.org1_admin = User.objects.create_user(
            email='admin1@test.com',
            username='admin1',
            password='password123',
            organization=self.org1,
            role=self.org1_admin_role
        )
        self.org1_user = User.objects.create_user(email='user1@test.com', username='user1', password='password123', organization=self.org1)

        # Org 2 Admin
        self.org2_admin_role = Role.objects.create(name='Org Admin', organization=self.org2)
        self.org2_admin = User.objects.create_user(
            email='admin2@test.com',
            username='admin2',
            password='password123',
            organization=self.org2,
            role=self.org2_admin_role
        )

        # Commissions
        self.comm1_org1 = Commission.objects.create(user=self.org1_user, organization=self.org1, total_sales=Decimal('10000.00'), start_date='2025-01-01', end_date='2025-01-31')
        self.comm2_org2 = Commission.objects.create(user=self.org2_admin, organization=self.org2, total_sales=Decimal('20000.00'), start_date='2025-01-01', end_date='2025-01-31')

        self.commission_list_url = reverse('commission-list')
        self.commission_detail_url = reverse('commission-detail', kwargs={'pk': self.comm1_org1.pk})

    def test_org_admin_can_list_own_commissions(self):
        self.client.force_authenticate(user=self.org1_admin)
        response = self.client.get(self.commission_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(Decimal(response.data[0]['total_sales']), self.comm1_org1.total_sales)

    def test_org_admin_cannot_list_other_org_commissions(self):
        self.client.force_authenticate(user=self.org2_admin)
        response = self.client.get(self.commission_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        total_sales = [c['total_sales'] for c in response.data]
        self.assertIn(str(self.comm2_org2.total_sales), total_sales)
        self.assertNotIn(str(self.comm1_org1.total_sales), total_sales)
        
    def test_super_admin_can_list_all_commissions(self):
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(self.commission_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), Commission.objects.count())

    def test_regular_user_cannot_list_commissions(self):
        self.client.force_authenticate(user=self.org1_user)
        response = self.client.get(self.commission_list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_org_admin_can_create_commission(self):
        self.client.force_authenticate(user=self.org1_admin)
        data = {
            "user": self.org1_user.id,
            "organization": self.org1.id,
            "total_sales": "5000.00",
            "start_date": "2025-02-01",
            "end_date": "2025-02-28"
        }
        response = self.client.post(self.commission_list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertTrue(Commission.objects.filter(user=self.org1_user, total_sales=Decimal('5000.00')).exists())

    def test_org_admin_can_update_commission(self):
        self.client.force_authenticate(user=self.org1_admin)
        data = {
            "user": self.org1_user.id,
            "organization": self.org1.id,
            "total_sales": "15000.00",
            "start_date": "2025-01-01",
            "end_date": "2025-01-31"
        }
        response = self.client.put(self.commission_detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.comm1_org1.refresh_from_db()
        self.assertEqual(self.comm1_org1.total_sales, Decimal('15000.00'))

    def test_org_admin_can_delete_commission(self):
        self.client.force_authenticate(user=self.org1_admin)
        response = self.client.delete(self.commission_detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Commission.objects.filter(pk=self.comm1_org1.pk).exists())

    def test_org_admin_cannot_access_other_org_commission(self):
        self.client.force_authenticate(user=self.org1_admin)
        other_org_url = reverse('commission-detail', kwargs={'pk': self.comm2_org2.pk})
        response = self.client.get(other_org_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_commission_calculation_on_save(self):
        """
        Test that the model's internal calculation logic is correct.
        """
        # Values from the setUp commission record.
        # It was saved once during setUp, so calculation has already run.
        commission = self.comm1_org1
        self.assertEqual(commission.converted_amount, Decimal('500.00')) # 10000 * 5%

        # Update the record and check recalculation
        commission.total_sales = Decimal('20000.00')
        commission.save()
        
        # 20000 * 5% = 1000
        self.assertEqual(commission.converted_amount, Decimal('1000.00'))

    def test_create_commission_record(self):
        """
        Ensure an Org Admin can create a new commission record.
        """
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('commission-list')
        data = {
            "user": self.org1_user.id,
            "organization": self.org1.id,
            "total_sales": "30000.00",
            "start_date": "2025-01-01",
            "end_date": "2025-01-31"
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # 30000 * 5% = 1500
        self.assertEqual(Decimal(response.data['converted_amount']), Decimal('1500.00'))
        self.assertEqual(response.data['user'], self.org1_user.id)
        self.assertEqual(response.data['organization'], self.org1.id)
