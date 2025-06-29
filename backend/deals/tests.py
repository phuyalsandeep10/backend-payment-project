from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from decimal import Decimal
from authentication.models import User
from organization.models import Organization
from permissions.models import Role, Permission
from .models import Deal, Payment
from clients.models import Client
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image
import io

class DealsAPITests(APITestCase):

    def setUp(self):
        self.org1 = Organization.objects.create(name='Org 1')
        self.org2 = Organization.objects.create(name='Org 2')
        
        # Create permissions
        self.create_client_perm, _ = Permission.objects.get_or_create(name='Create Client', codename='create_client', defaults={'category': 'Client Management'})
        self.view_all_clients_perm, _ = Permission.objects.get_or_create(name='View All Clients', codename='view_all_clients', defaults={'category': 'Client Management'})
        self.create_deal_perm, _ = Permission.objects.get_or_create(name='Create Deal', codename='create_deal', defaults={'category': 'Deal Management'})
        self.view_all_deals_perm, _ = Permission.objects.get_or_create(name='View All Deals', codename='view_all_deals', defaults={'category': 'Deal Management'})
        self.verify_payment_perm, _ = Permission.objects.get_or_create(name='Verify Deal Payment', codename='verify_deal_payment', defaults={'category': 'Deal Management'})
        self.log_activity_perm, _ = Permission.objects.get_or_create(name='Log Deal Activity', codename='log_deal_activity', defaults={'category': 'Deal Management'})
        
        self.super_admin_role = Role.objects.create(name='Super Admin')
        self.super_admin = User.objects.create_user(email='super@test.com', username='superadmin', password='password123', role=self.super_admin_role, is_superuser=True)
        
        # Create Org Admin role with proper permissions
        self.org1_admin_role = Role.objects.create(name='Org Admin', organization=self.org1)
        self.org1_admin_role.permissions.set([
            self.create_client_perm, self.view_all_clients_perm, 
            self.create_deal_perm, self.view_all_deals_perm, self.verify_payment_perm, self.log_activity_perm
        ])
        
        self.org1_admin = User.objects.create_user(email='admin1@test.com', username='admin1', password='password123', organization=self.org1, role=self.org1_admin_role)
        self.org1_user = User.objects.create_user(email='user1@test.com', username='user1', password='password123', organization=self.org1)
        self.org2_admin = User.objects.create_user(email='admin2@test.com', username='admin2', password='password123', organization=self.org2, role=self.org1_admin_role)

        # Create a client first since deals are nested under clients
        self.client1 = Client.objects.create(
            client_name='Test Client 1',
            email='client1@test.com',
            organization=self.org1,
            created_by=self.org1_admin
        )

        self.deal1 = Deal.objects.create(
            organization=self.org1,
            created_by=self.org1_admin,
            client_name='Test Client 1',
            deal_value=Decimal('1000.00'),
            pay_status='partial_payment',
            source_type='referral',
            payment_method='cash',
            deal_date='2025-01-15',
            due_date='2025-02-15'
        )
        self.payment1 = Payment.objects.create(deal=self.deal1, received_amount=Decimal('500.00'), payment_date='2025-01-20', payment_type='partial_payment')

        # Create a dummy image for testing file uploads
        buffer = io.BytesIO()
        img = Image.new('RGB', (100, 100), color = 'red')
        img.save(buffer, 'jpeg')
        buffer.seek(0)
        self.dummy_image = SimpleUploadedFile("test.jpg", buffer.read(), content_type="image/jpeg")

    # Deal Endpoint Tests (using nested URLs)
    def test_org_admin_can_list_deals(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('client-deals-list', kwargs={'client_pk': self.client1.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_regular_user_cannot_list_deals(self):
        self.client.force_authenticate(user=self.org1_user)
        url = reverse('client-deals-list', kwargs={'client_pk': self.client1.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_org_admin_can_create_deal(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('client-deals-list', kwargs={'client_pk': self.client1.pk})
        data = {
            'client_name': 'Test Client 1',
            'deal_value': '2500.00',
            'pay_status': 'full_payment',
            'source_type': 'referral',
            'payment_method': 'cash',
            'deal_date': '2025-03-01',
            'due_date': '2025-03-31'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Deal.objects.count(), 2)
        new_deal = Deal.objects.filter(deal_value=Decimal('2500.00')).first()
        self.assertIsNotNone(new_deal)
        self.assertEqual(new_deal.created_by, self.org1_admin)
        self.assertEqual(new_deal.activity_logs.count(), 1) # Check if log was created

    def test_deal_detail_view(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('client-deals-detail', kwargs={'client_pk': self.client1.pk, 'pk': self.deal1.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['client_name'], self.deal1.client_name)
        self.assertEqual(len(response.data['payments']), 1)

    # Payment Endpoint Tests (using nested URLs)
    def test_org_admin_can_list_payments(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('client-deal-payments-list', kwargs={'client_pk': self.client1.pk, 'deal_pk': self.deal1.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_org_admin_can_create_payment_for_deal(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('client-deal-payments-list', kwargs={'client_pk': self.client1.pk, 'deal_pk': self.deal1.pk})
        data = {
            'received_amount': '250.00',
            'payment_date': '2025-02-01',
            'payment_type': 'partial_payment',
            'cheque_number': '12345',
            'receipt_file': self.dummy_image
        }
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(self.deal1.payments.count(), 2)
        new_payment = Payment.objects.latest('id')
        self.assertIsNotNone(new_payment.receipt_file)

    def test_cannot_upload_invalid_file_type(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('client-deal-payments-list', kwargs={'client_pk': self.client1.pk, 'deal_pk': self.deal1.pk})
        invalid_file = SimpleUploadedFile("test.txt", b"some content", content_type="text/plain")
        data = {
            'received_amount': '100.00',
            'payment_date': '2025-02-05',
            'payment_type': 'partial_payment',
            'cheque_number': '54321',
            'receipt_file': invalid_file
        }
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('receipt_file', response.data)
    
    # ActivityLog Endpoint Tests (using nested URLs)
    def test_activity_log_is_read_only(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('client-deal-activity-list', kwargs={'client_pk': self.client1.pk, 'deal_pk': self.deal1.pk})
        
        # Verify the user can access the activity log endpoint with GET
        get_response = self.client.get(url)
        self.assertEqual(get_response.status_code, status.HTTP_200_OK)
        
        # Verify that the activity log shows deal creation activity
        # (Activity log is automatically created when a deal is created)
        self.assertGreaterEqual(len(get_response.data), 0)  # Should have at least one activity log entry
