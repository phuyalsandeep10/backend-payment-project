from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from decimal import Decimal
from authentication.models import User
from organization.models import Organization
from permissions.models import Role
from .models import Deal, Payment
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image
import io

class DealsAPITests(APITestCase):

    def setUp(self):
        self.org1 = Organization.objects.create(name='Org 1')
        self.org2 = Organization.objects.create(name='Org 2')
        self.super_admin_role = Role.objects.create(name='Super Admin')
        self.super_admin = User.objects.create_user(email='super@test.com', username='superadmin', password='password123', role=self.super_admin_role, is_superuser=True)
        self.org1_admin_role = Role.objects.create(name='Org Admin', organization=self.org1)
        self.org1_admin = User.objects.create_user(email='admin1@test.com', username='admin1', password='password123', organization=self.org1, role=self.org1_admin_role)
        self.org1_user = User.objects.create_user(email='user1@test.com', username='user1', password='password123', organization=self.org1)
        self.org2_admin = User.objects.create_user(email='admin2@test.com', username='admin2', password='password123', organization=self.org2, role=self.org1_admin_role)

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

    # Deal Endpoint Tests
    def test_org_admin_can_list_deals(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('deal-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_regular_user_cannot_list_deals(self):
        self.client.force_authenticate(user=self.org1_user)
        url = reverse('deal-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_org_admin_can_create_deal(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('deal-list')
        data = {
            'client_name': 'New Client',
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
        new_deal = Deal.objects.get(client_name='New Client')
        self.assertEqual(new_deal.created_by, self.org1_admin)
        self.assertEqual(new_deal.activity_logs.count(), 1) # Check if log was created

    def test_deal_detail_view(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('deal-detail', kwargs={'pk': self.deal1.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['client_name'], self.deal1.client_name)
        self.assertEqual(len(response.data['payments']), 1)

    # Payment Endpoint Tests
    def test_org_admin_can_list_payments(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('payment-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_org_admin_can_create_payment_for_deal(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('payment-list')
        data = {
            'deal': self.deal1.pk,
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
        url = reverse('payment-list')
        invalid_file = SimpleUploadedFile("test.txt", b"some content", content_type="text/plain")
        data = {
            'deal': self.deal1.pk,
            'received_amount': '100.00',
            'payment_date': '2025-02-05',
            'payment_type': 'partial_payment',
            'cheque_number': '54321',
            'receipt_file': invalid_file
        }
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('receipt_file', response.data)
    
    # ActivityLog Endpoint Tests
    def test_activity_log_is_read_only(self):
        self.client.force_authenticate(user=self.org1_admin)
        url = reverse('activity-log-list')
        data = {'deal': self.deal1.pk, 'message': 'This should not work'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
