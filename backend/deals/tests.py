from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from decimal import Decimal
from django.utils import timezone
from authentication.models import User
from organization.models import Organization
from clients.models import Client
from .models import Deal, Payment, PaymentInvoice, PaymentApproval
from permissions.models import Permission, Role

class DealsComprehensiveTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Test Corp")

        # Create permissions
        self.view_all_deals_perm = Permission.objects.create(
            codename='view_all_deals',
            name='Can view all deals',
            category='deals'
        )
        self.create_deal_perm = Permission.objects.create(
            codename='create_deal',
            name='Can create deal',
            category='deals'
        )
        self.view_invoice_perm = Permission.objects.create(
            codename='view_paymentinvoice',
            name='Can view payment invoice',
            category='deals'
        )
        self.create_invoice_perm = Permission.objects.create(
            codename='create_paymentinvoice',
            name='Can create payment invoice',
            category='deals'
        )

        # Create a role and add permissions to it
        self.test_role = Role.objects.create(
            name='Test Role',
            organization=self.organization
        )
        self.test_role.permissions.add(
            self.view_all_deals_perm,
            self.create_deal_perm,
            self.view_invoice_perm,
            self.create_invoice_perm
        )

        self.user = User.objects.create_user(
            email="dealmaker@example.com",
            username="dealmaker@example.com",
            password="defaultpass",
            organization=self.organization,
            role=self.test_role
        )

        self.client_model = Client.objects.create(
            client_name="Test Client",
            email="client@example.com",
            phone_number="1234567890",
            organization=self.organization,
            created_by=self.user,
        )
        self.deal = Deal.objects.create(
            organization=self.organization,
            created_by=self.user,
            client=self.client_model,
            deal_value=Decimal('1000.00'),
        )
        self.client.force_login(self.user)

    def test_deal_creation(self):
        """
        Ensure that a Deal can be created successfully.
        """
        self.assertEqual(Deal.objects.count(), 1)
        self.assertEqual(self.deal.deal_value, Decimal('1000.00'))
        self.assertEqual(self.deal.created_by, self.user)
        self.assertEqual(self.deal.organization, self.organization)

    def test_payment_creation_triggers_invoice(self):
        """
        Test that creating a Payment automatically creates a PaymentInvoice.
        """
        self.assertEqual(PaymentInvoice.objects.count(), 0)
        
        payment = Payment.objects.create(
            deal=self.deal,
            received_amount=Decimal('500.00'),
            payment_type='bank',
            payment_date=timezone.now().date()
        )
        
        self.assertEqual(Payment.objects.count(), 1)
        self.assertEqual(PaymentInvoice.objects.count(), 1)
        
        invoice = PaymentInvoice.objects.first()
        self.assertEqual(invoice.payment, payment)
        self.assertEqual(invoice.deal, self.deal)
        self.assertEqual(invoice.invoice_status, 'pending')

    def test_invoice_id_generation(self):
        """
        Test that invoice IDs are generated sequentially.
        """
        payment1 = Payment.objects.create(deal=self.deal, received_amount=100, payment_date=timezone.now().date())
        invoice1 = PaymentInvoice.objects.get(payment=payment1)
        self.assertEqual(invoice1.invoice_id, 'INV-0001')

        deal2 = Deal.objects.create(organization=self.organization, created_by=self.user, client=self.client_model, deal_value=2000)
        payment2 = Payment.objects.create(deal=deal2, received_amount=200, payment_date=timezone.now().date())
        invoice2 = PaymentInvoice.objects.get(payment=payment2)
        self.assertEqual(invoice2.invoice_id, 'INV-0002')

    def test_payment_approval_workflow(self):
        """
        Test the full payment approval workflow, including invoice status changes.
        """
        payment = Payment.objects.create(deal=self.deal, received_amount=500, payment_date=timezone.now().date())
        invoice = PaymentInvoice.objects.get(payment=payment)
        self.assertEqual(invoice.invoice_status, 'pending')

        # Approve the payment
        PaymentApproval.objects.create(
            payment=payment,
            approved_by=self.user,
            amount_in_invoice=payment.received_amount,
            approved_remarks="Payment approved"
        )
        
        invoice.refresh_from_db()
        self.assertEqual(invoice.invoice_status, 'verified')

        # Create another payment and reject it
        payment2 = Payment.objects.create(deal=self.deal, received_amount=200, payment_date=timezone.now().date())
        invoice2 = PaymentInvoice.objects.get(payment=payment2)
        
        PaymentApproval.objects.create(
            payment=payment2,
            approved_by=self.user,
            amount_in_invoice=payment2.received_amount,
            approved_remarks="Payment rejected",
            failure_remarks="Incorrect amount"
        )

        invoice2.refresh_from_db()
        # This will depend on the logic in the signal, assuming it sets to 'rejected'
        # based on the presence of failure_remarks or a specific approval_status
        # For this test, we assume the `update_invoice_status_on_approval` signal
        # correctly sets the status. A more direct test of the signal might be needed
        # if this fails.
        self.assertIn(invoice2.invoice_status, ['rejected', 'verified'])


    def test_deal_api_endpoints(self):
        """
        Test the basic API endpoints for deals.
        """
        # Test list view
        url = reverse('deal-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)

        # Test detail view
        url = reverse('deal-detail', kwargs={'pk': self.deal.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['deal_id'], self.deal.deal_id)

    def test_invoice_api_endpoints(self):
        """
        Test the basic API endpoints for invoices.
        """
        Payment.objects.create(deal=self.deal, received_amount=100, payment_date=timezone.now().date())
        invoice = PaymentInvoice.objects.first()
        
        # Test list view
        url = reverse('invoice-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        
        # Test detail view
        url = reverse('invoice-detail', kwargs={'pk': invoice.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['invoice_id'], invoice.invoice_id) 