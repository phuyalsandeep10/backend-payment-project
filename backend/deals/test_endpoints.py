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
from deals.models import Deal, Payment, ActivityLog, PaymentInvoice, PaymentApproval
from decimal import Decimal
from datetime import date

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
        
        # Invoice and Approval permissions
        cls.can_create_invoice, _ = Permission.objects.get_or_create(codename='create_paymentinvoice', name='Can create invoice', category='Invoice')
        cls.can_view_invoice, _ = Permission.objects.get_or_create(codename='view_paymentinvoice', name='Can view invoice', category='Invoice')
        cls.can_edit_invoice, _ = Permission.objects.get_or_create(codename='edit_paymentinvoice', name='Can edit invoice', category='Invoice')
        cls.can_delete_invoice, _ = Permission.objects.get_or_create(codename='delete_paymentinvoice', name='Can delete invoice', category='Invoice')
        cls.can_create_approval, _ = Permission.objects.get_or_create(codename='create_paymentapproval', name='Can create approval', category='Approval')
        cls.can_view_approval, _ = Permission.objects.get_or_create(codename='view_paymentapproval', name='Can view approval', category='Approval')
        cls.can_edit_approval, _ = Permission.objects.get_or_create(codename='edit_paymentapproval', name='Can edit approval', category='Approval')
        cls.can_delete_approval, _ = Permission.objects.get_or_create(codename='delete_paymentapproval', name='Can delete approval', category='Approval')
        
        cls.role1.permissions.add(
            cls.can_create_deal,
            cls.can_edit_deal,
            cls.can_delete_deal,
            cls.can_view_all_deals,
            cls.can_create_invoice,
            cls.can_view_invoice,
            cls.can_edit_invoice,
            cls.can_delete_invoice,
            cls.can_create_approval,
            cls.can_view_approval,
            cls.can_edit_approval,
            cls.can_delete_approval,
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
        
        # Handle paginated response
        if 'results' in response.data:
            deals_data = response.data['results']
        else:
            deals_data = response.data
            
        # Check that at least our deal is in the response
        self.assertGreaterEqual(len(deals_data), 1)
        # Check that our deal is in the response
        deal_ids = [deal['deal_id'] for deal in deals_data]
        self.assertIn(self.deal1.deal_id, deal_ids)

    def test_create_deal(self):
        """
        A user with permission can create a deal.
        """
        initial_count = Deal.objects.count()
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
        self.assertEqual(Deal.objects.count(), initial_count + 1)

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
        initial_count = Deal.objects.count()
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Deal.objects.count(), initial_count - 1)
        # Verify the specific deal is deleted
        self.assertFalse(Deal.objects.filter(pk=self.deal1.pk).exists())

    def test_activity_log_created_on_deal_creation(self):
        """
        An activity log should be created when a deal is created.
        """
        # Check that there's at least one activity log for our deal
        logs = ActivityLog.objects.filter(deal=self.deal1)
        self.assertGreaterEqual(logs.count(), 1)
        # Check that the creation log exists
        creation_log = logs.filter(message__icontains=f"Deal created for {self.deal1.client.client_name}").first()
        self.assertIsNotNone(creation_log)
        self.assertEqual(creation_log.deal, self.deal1)
        
    def test_activity_log_created_on_deal_update(self):
        """
        An activity log should be created when a deal's verification_status is updated.
        """
        initial_log_count = ActivityLog.objects.filter(deal=self.deal1).count()
        self.deal1.verification_status = 'verified'
        self.deal1.save()
        # Check that a new log was created for this deal
        new_log_count = ActivityLog.objects.filter(deal=self.deal1).count()
        self.assertEqual(new_log_count, initial_log_count + 1)
        # Check that the verification update log exists
        verification_log = ActivityLog.objects.filter(
            deal=self.deal1,
            message__icontains=f"Deal verification_status updated to {self.deal1.get_verification_status_display()}"
        ).first()
        self.assertIsNotNone(verification_log)
        self.assertEqual(verification_log.deal, self.deal1)

    def test_payment_creates_invoice_automatically(self):
        """
        Test that creating a payment automatically creates a PaymentInvoice via signals.
        """
        initial_invoice_count = PaymentInvoice.objects.count()
        
        # Create a payment
        payment = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('5000.00'),
            payment_type='bank'
        )
        
        # Check that an invoice was created
        self.assertEqual(PaymentInvoice.objects.count(), initial_invoice_count + 1)
        
        # Check that the invoice is linked to the payment and deal
        invoice = PaymentInvoice.objects.get(payment=payment)
        self.assertEqual(invoice.deal, self.deal1)
        self.assertEqual(invoice.payment, payment)
        self.assertEqual(invoice.invoice_status, 'pending')
        self.assertTrue(invoice.invoice_id.startswith('INV-'))

    def test_invoice_id_generation(self):
        """
        Test that invoice IDs are generated correctly and sequentially.
        """
        # Create multiple payments to generate multiple invoices
        payment1 = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('2000.00'),
            payment_type='bank'
        )
        
        payment2 = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('3000.00'),
            payment_type='cash'
        )
        
        invoice1 = PaymentInvoice.objects.get(payment=payment1)
        invoice2 = PaymentInvoice.objects.get(payment=payment2)
        
        # Check that invoice IDs are sequential
        self.assertTrue(invoice1.invoice_id.startswith('INV-'))
        self.assertTrue(invoice2.invoice_id.startswith('INV-'))
        
        # Extract numbers and verify they're sequential
        id1_num = int(invoice1.invoice_id[4:])
        id2_num = int(invoice2.invoice_id[4:])
        self.assertEqual(id2_num, id1_num + 1)

    def test_invoice_list_endpoint(self):
        """
        Test the invoice list endpoint.
        """
        # Create a payment to generate an invoice
        payment = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('1000.00'),
            payment_type='bank'
        )
        
        url = reverse('invoice-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Handle paginated response
        if 'results' in response.data:
            invoices_data = response.data['results']
        else:
            invoices_data = response.data
            
        self.assertGreaterEqual(len(invoices_data), 1)
        
        # Check that our invoice is in the response
        invoice_ids = [inv['invoice_id'] for inv in invoices_data]
        invoice = PaymentInvoice.objects.get(payment=payment)
        self.assertIn(invoice.invoice_id, invoice_ids)

    def test_invoice_detail_endpoint(self):
        """
        Test the invoice detail endpoint.
        """
        # Create a payment to generate an invoice
        payment = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('1500.00'),
            payment_type='cheque',
            cheque_number='CHQ12345'
        )
        
        invoice = PaymentInvoice.objects.get(payment=payment)
        url = reverse('invoice-detail', kwargs={'pk': invoice.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['invoice_id'], invoice.invoice_id)
        self.assertEqual(response.data['invoice_status'], 'pending')

    def test_payment_approval_creation(self):
        """
        Test creating a payment approval.
        """
        # Create a payment first
        payment = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('2500.00'),
            payment_type='bank'
        )
        
        # Create an approval
        approval = PaymentApproval.objects.create(
            payment=payment,
            approved_by=self.user1,
            approved_remarks='Payment verified and approved',
            amount_in_invoice=Decimal('2500.00')
        )
        
        self.assertEqual(approval.deal, self.deal1)  # Should be auto-set
        self.assertEqual(approval.payment, payment)
        self.assertEqual(approval.approved_by, self.user1)
        self.assertEqual(approval.amount_in_invoice, Decimal('2500.00'))

    def test_invoice_status_updates_on_approval(self):
        """
        Test that invoice status updates when an approval is created.
        """
        # Create a payment (which creates an invoice)
        payment = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('3000.00'),
            payment_type='bank'
        )
        
        invoice = PaymentInvoice.objects.get(payment=payment)
        self.assertEqual(invoice.invoice_status, 'pending')
        
        # Create an approval without failure remarks (should be verified)
        PaymentApproval.objects.create(
            payment=payment,
            approved_by=self.user1,
            approved_remarks='Payment approved',
            amount_in_invoice=Decimal('3000.00')
        )
        
        # Check that invoice status is updated
        invoice.refresh_from_db()
        self.assertEqual(invoice.invoice_status, 'verified')

    def test_invoice_status_updates_on_rejection(self):
        """
        Test that invoice status updates to rejected when approval has failure remarks.
        """
        # Create a payment (which creates an invoice)
        payment = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('1000.00'),
            payment_type='cheque',
            cheque_number='CHQ67890'
        )
        
        invoice = PaymentInvoice.objects.get(payment=payment)
        self.assertEqual(invoice.invoice_status, 'pending')
        
        # Create an approval with failure remarks (should be rejected)
        PaymentApproval.objects.create(
            payment=payment,
            approved_by=self.user1,
            approved_remarks='Cheque bounced',
            failure_remarks='cheque_bounce',
            amount_in_invoice=Decimal('1000.00')
        )
        
        # Check that invoice status is updated to rejected
        invoice.refresh_from_db()
        self.assertEqual(invoice.invoice_status, 'rejected')

    def test_approval_list_endpoint(self):
        """
        Test the approval list endpoint.
        """
        # Create a payment and approval
        payment = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('1200.00'),
            payment_type='cash'
        )
        
        approval = PaymentApproval.objects.create(
            payment=payment,
            approved_by=self.user1,
            approved_remarks='Cash payment verified',
            amount_in_invoice=Decimal('1200.00')
        )
        
        url = reverse('approval-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Handle paginated response
        if 'results' in response.data:
            approvals_data = response.data['results']
        else:
            approvals_data = response.data
            
        self.assertGreaterEqual(len(approvals_data), 1)

    def test_approval_detail_endpoint(self):
        """
        Test the approval detail endpoint.
        """
        # Create a payment and approval
        payment = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('800.00'),
            payment_type='wallet'
        )
        
        approval = PaymentApproval.objects.create(
            payment=payment,
            approved_by=self.user1,
            approved_remarks='Mobile wallet payment confirmed',
            amount_in_invoice=Decimal('800.00')
        )
        
        url = reverse('approval-detail', kwargs={'pk': approval.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['approved_remarks'], 'Mobile wallet payment confirmed')
        self.assertEqual(str(response.data['amount_in_invoice']), '800.00')

    def test_deal_invoices_action(self):
        """
        Test the custom action to get invoices for a deal.
        """
        # Create multiple payments for the same deal
        payment1 = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('500.00'),
            payment_type='bank'
        )
        
        payment2 = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('700.00'),
            payment_type='cash'
        )
        
        url = reverse('deal-list-invoices', kwargs={'pk': self.deal1.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
        
        # Check that both invoices are returned
        invoice_ids = [inv['invoice_id'] for inv in response.data]
        invoice1 = PaymentInvoice.objects.get(payment=payment1)
        invoice2 = PaymentInvoice.objects.get(payment=payment2)
        
        self.assertIn(invoice1.invoice_id, invoice_ids)
        self.assertIn(invoice2.invoice_id, invoice_ids)

    def test_invoice_organization_filtering(self):
        """
        Test that invoices are properly filtered by organization.
        """
        # Create another organization and user
        org2 = Organization.objects.create(name="Org 2")
        role2 = Role.objects.create(name='Admin2', organization=org2)
        role2.permissions.add(
            self.can_view_all_deals,
            self.can_create_invoice,
            self.can_view_invoice,
            self.can_edit_invoice,
            self.can_delete_invoice,
            self.can_create_approval,
            self.can_view_approval,
            self.can_edit_approval,
            self.can_delete_approval,
        )
        
        user2 = User.objects.create_user(
            username='user2', 
            email='user2@example.com', 
            password='password123', 
            organization=org2, 
            role=role2
        )
        
        client2 = Client.objects.create(
            client_name="Client 2",
            created_by=user2,
            organization=org2,
            email="client2@example.com",
            phone_number="+1234567891"
        )
        
        deal2 = Deal.objects.create(
            organization=org2,
            client=client2,
            created_by=user2,
            payment_status='initial payment',
            source_type='linkedin',
            deal_value=Decimal('5000.00'),
            deal_date='2024-01-01',
            due_date='2024-02-01',
            payment_method='bank',
            verification_status='pending'
        )
        
        # Create payments for both organizations
        payment1 = Payment.objects.create(
            deal=self.deal1,
            payment_date=date.today(),
            received_amount=Decimal('1000.00'),
            payment_type='bank'
        )
        
        payment2 = Payment.objects.create(
            deal=deal2,
            payment_date=date.today(),
            received_amount=Decimal('2000.00'),
            payment_type='bank'
        )
        
        # Test that user1 only sees invoices from their organization
        url = reverse('invoice-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Handle paginated response
        if 'results' in response.data:
            invoices_data = response.data['results']
        else:
            invoices_data = response.data
        
        # Should only see invoices from org1
        for invoice_data in invoices_data:
            invoice = PaymentInvoice.objects.get(pk=invoice_data['id'])
            self.assertEqual(invoice.deal.organization, self.organization1) 