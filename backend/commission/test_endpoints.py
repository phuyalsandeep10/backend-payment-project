import uuid
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from authentication.models import User
from organization.models import Organization
from permissions.models import Role, Permission
from deals.models import Deal
from commission.models import Commission
from decimal import Decimal
from clients.models import Client

class CommissionEndpointTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        # Setup Organizations
        cls.organization1 = Organization.objects.create(name="Org 1")

        # Setup Roles
        cls.role1 = Role.objects.create(name='Admin', organization=cls.organization1)
        
        # Setup Permissions
        cls.can_view_commission, _ = Permission.objects.get_or_create(codename='view_all_commissions', name='Can view all commissions', category='Commission')
        cls.can_create_commission, _ = Permission.objects.get_or_create(codename='create_commission', name='Can create commission', category='Commission')
        cls.role1.permissions.add(cls.can_view_commission, cls.can_create_commission)

        # Setup Users
        cls.user1 = User.objects.create_user(username='user1', email='user1@example.com', password='password123', organization=cls.organization1, role=cls.role1)

    def setUp(self):
        # Authenticate User 1
        self.client.force_authenticate(user=self.user1)

        # Setup Client and Deal
        self.client1 = Client.objects.create(
            client_name="Test Client",
            created_by=self.user1,
            organization=self.organization1,
            email="client@example.com",
            phone_number="+1234567890"
        )
        self.deal1 = Deal.objects.create(
            organization=self.organization1,
            client=self.client1,
            created_by=self.user1,
            payment_status='full_payment',
            source_type='google',
            deal_value=Decimal('50000.00'),
            deal_date='2024-01-01',
            due_date='2024-02-01',
            payment_method='bank',
            verification_status='pending',
        )

        # URLS
        self.list_create_url = reverse('commission-list')

    def test_create_and_calculate_commission(self):
        """
        Ensure a commission can be created and the converted_amount is calculated correctly.
        """
        data = {
            "user": self.user1.pk,
            "organization": self.organization1.pk,
            "total_sales": "100000.00",
            "start_date": "2024-01-01",
            "end_date": "2024-01-31",
            "commission_percentage": "10.00"
        }
        response = self.client.post(self.list_create_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        commission = Commission.objects.get(pk=response.data['id'])
        self.assertEqual(commission.user, self.user1)
        self.assertEqual(commission.total_sales, Decimal('100000.00'))
        # 100000.00 * (10.00 / 100) = 10000.00
        self.assertEqual(commission.converted_amount, Decimal('10000.00'))

    def test_list_commissions(self):
        """
        Ensure a user can list commissions.
        """
        Commission.objects.create(
            user=self.user1,
            total_sales=Decimal("50000.00"),
            start_date="2024-02-01",
            end_date="2024-02-28",
        )
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['user'], self.user1.pk)

    # This test is no longer valid and will be removed.
    # def test_commission_creation_on_deal_verification(self): 