import uuid
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from authentication.models import User
from organization.models import Organization
from team.models import Team
from permissions.models import Role, Permission
from clients.models import Client
from project.models import Project
from deals.models import Deal, Payment, ActivityLog
from decimal import Decimal

class DealEndpointTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        # Setup Organizations
        cls.organization1 = Organization.objects.create(name="Org 1")

        # Setup Roles
        cls.role1 = Role.objects.create(name='Admin', organization=cls.organization1)
        
        # Setup Permissions
        cls.can_create_deal, _ = Permission.objects.get_or_create(codename='create_deal', name='Can create deal', category='Deal')
        cls.can_edit_deal, _ = Permission.objects.get_or_create(codename='edit_deal', name='Can edit deal', category='Deal')
        cls.can_delete_deal, _ = Permission.objects.get_or_create(codename='delete_deal', name='Can delete deal', category='Deal')
        cls.can_view_all_deals, _ = Permission.objects.get_or_create(codename='view_all_deals', name='Can view all deals', category='Deal')
        
        cls.role1.permissions.add(
            cls.can_create_deal,
            cls.can_edit_deal,
            cls.can_delete_deal,
            cls.can_view_all_deals,
        )

        # Setup Users
        cls.user1 = User.objects.create_user(username='user1', email='user1@example.com', password='password123', organization=cls.organization1, role=cls.role1)

        # Setup Client
        cls.client1 = Client.objects.create(
            client_name="Test Client", 
            created_by=cls.user1,
            organization=cls.organization1,
            email="client@example.com",
            phone_number="+1234567890"
        )

        # Setup Project
        cls.project1 = Project.objects.create(name="Test Project", created_by=cls.user1)

    def setUp(self):
        # Authenticate User 1
        self.client.force_authenticate(user=self.user1)

        # Setup Deal
        self.deal1 = Deal.objects.create(
            organization=self.organization1,
            client=self.client1,
            created_by=self.user1,
            payment_status='initial payment',
            source_type='google',
            deal_value=Decimal('10000.00'),
            deal_date='2024-01-01',
            due_date='2024-02-01',
            payment_method='bank',
            verification_status='pending',
        )

        # URLS
        self.list_create_url = reverse('deal-list')
        self.detail_url = reverse('deal-detail', kwargs={'pk': self.deal1.pk})

    def test_list_deals(self):
        """
        A user should be able to list deals.
        """
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['deal_id'], self.deal1.deal_id)

    def test_create_deal(self):
        """
        A user with permission can create a deal.
        """
        data = {
            "client_id": self.client1.pk,
            "organization": self.organization1.pk,
            "payment_status": "initial payment",
            "source_type": "referral",
            "deal_value": "25000.00",
            "deal_date": "2024-03-01",
            "due_date": "2024-04-01",
            "payment_method": "cash",
        }
        response = self.client.post(self.list_create_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Deal.objects.count(), 2)

    def test_retrieve_deal(self):
        """
        A user should be able to retrieve a deal.
        """
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['deal_id'], self.deal1.deal_id)

    def test_update_deal(self):
        """
        A user with permission can update a deal.
        """
        data = {"deal_value": "12000.00"}
        response = self.client.patch(self.detail_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.deal1.refresh_from_db()
        self.assertEqual(self.deal1.deal_value, Decimal('12000.00'))

    def test_delete_deal(self):
        """
        A user with permission can delete a deal.
        """
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Deal.objects.count(), 0)

    def test_activity_log_created_on_deal_creation(self):
        """
        An activity log should be created when a deal is created.
        """
        self.assertEqual(ActivityLog.objects.count(), 1)
        log = ActivityLog.objects.first()
        self.assertEqual(log.deal, self.deal1)
        self.assertIn(f"Deal created for {self.deal1.client.client_name}", log.message)
        
    def test_activity_log_created_on_deal_update(self):
        """
        An activity log should be created when a deal's verification_status is updated.
        """
        initial_log_count = ActivityLog.objects.count()
        self.deal1.verification_status = 'verified'
        self.deal1.save()
        self.assertEqual(ActivityLog.objects.count(), initial_log_count + 1)
        log = ActivityLog.objects.latest('timestamp')
        self.assertEqual(log.deal, self.deal1)
        self.assertIn(f"Deal verification_status updated to {self.deal1.get_verification_status_display()}", log.message) 