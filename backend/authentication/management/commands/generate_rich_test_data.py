from django.core.management.base import BaseCommand
from django.db import transaction
from authentication.models import User
from clients.models import Client
from deals.models import Deal, Payment, PaymentInvoice, PaymentApproval, ActivityLog
from project.models import Project
from commission.models import Commission
from Verifier_dashboard.models import AuditLogs
from notifications.models import Notification
from datetime import timedelta
from decimal import Decimal
import random
from faker import Faker
from django.utils import timezone

class Command(BaseCommand):
    help = 'Generates a rich and varied dataset on top of existing data for testing purposes.'

    @transaction.atomic
    def handle(self, *args, **options):
        self.faker = Faker()
        self.stdout.write(self.style.HTTP_INFO("--- Generating Rich & Varied Mock Data ---"))

        salespersons = list(User.objects.filter(role__name__icontains='Salesperson'))
        verifiers = list(User.objects.filter(role__name__icontains='Verifier'))
        clients = list(Client.objects.all())
        projects = list(Project.objects.all())

        if not all([salespersons, verifiers, clients, projects]):
            self.stdout.write(self.style.ERROR("Key data (Users, Clients, Projects) not found. Please run 'initialize_app' first."))
            return
            
        self.create_additional_deals(salespersons, clients, projects, verifiers, 50)
        self.create_guaranteed_recent_data(salespersons[0], clients, projects, verifiers)

        self.stdout.write(self.style.SUCCESS("✅ Rich mock data generation completed successfully!"))

    def create_additional_deals(self, salespersons, clients, projects, verifiers, count):
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating {count} Additional Random Deals ---"))
        for _ in range(count):
            salesperson = random.choice(salespersons)
            deal_date = self.faker.date_between(start_date='-4M', end_date='-1M')
            deal = Deal.objects.create(
                organization=salesperson.organization,
                client=random.choice(clients),
                project=random.choice(projects) if projects and random.random() > 0.5 else None,
                deal_name=self.faker.bs().title(),
                deal_value=Decimal(random.randint(1000, 25000)),
                deal_date=deal_date,
                payment_method=random.choice([c[0] for c in Deal.PAYMENT_METHOD_CHOICES]),
                source_type=random.choice([c[0] for c in Deal.SOURCE_TYPES]),
                created_by=salesperson,
            )
            ActivityLog.objects.create(deal=deal, message=f"Deal created by {deal.created_by.username}.")
            
            scenario = random.choice(['verified_full', 'verified_partial', 'multi_partial', 'rejected', 'refunded', 'bad_debt'])
            self.process_deal_payment_and_verification(deal, verifiers, scenario)

    def create_guaranteed_recent_data(self, salesperson, clients, projects, verifiers):
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating 5 Guaranteed Recent Deals for {salesperson.username} ---"))
        today = timezone.now().date()
        for i in range(5):
            deal_date = today - timedelta(days=i)
            deal = Deal.objects.create(organization=salesperson.organization, client=random.choice(clients), project=random.choice(projects) if projects and random.random() > 0.5 else None, deal_name=f"Streak Deal Day {i+1}", deal_value=Decimal(random.randint(500, 2000)), deal_date=deal_date, payment_method='bank', source_type='referral', created_by=salesperson, payment_status='initial payment')
            self.create_payment_flow(deal, deal.deal_value, deal_date, random.choice(verifiers), 'verified_full')

    def process_deal_payment_and_verification(self, deal, verifiers, scenario):
        verifier = random.choice(verifiers)
        payment_date = deal.deal_date + timedelta(days=random.randint(1, 10))
        
        if scenario == 'multi_partial':
            remaining_value = deal.deal_value
            for i in range(random.randint(2, 4)):
                if remaining_value <= 0: break
                payment_amount = (remaining_value / 2) * Decimal(random.uniform(0.5, 0.9))
                self.create_payment_flow(deal, payment_amount, payment_date + timedelta(days=i*10), verifier, 'verified' if i < 2 else 'pending')
                remaining_value -= payment_amount
            return

        payment_amount = deal.deal_value * Decimal(random.uniform(0.7, 1.0) if scenario == 'verified_full' else 0.5)
        self.create_payment_flow(deal, payment_amount, payment_date, verifier, scenario)
        
    def create_payment_flow(self, deal, amount, payment_date, verifier, final_status):
        payment = Payment.objects.create(deal=deal, received_amount=amount.quantize(Decimal('0.01')), payment_date=payment_date, payment_type=deal.payment_method)
        invoice = PaymentInvoice.objects.get(payment=payment)
        
        status_map = {'verified_full': 'verified', 'verified_partial': 'verified', 'rejected': 'rejected', 'refunded': 'refunded', 'bad_debt': 'bad_debt'}
        invoice.invoice_status = status_map.get(final_status, 'pending')
        
        if invoice.invoice_status == 'verified':
            deal.verification_status = 'verified'
            deal.payment_status = 'full_payment' if amount >= deal.deal_value else 'initial payment'
            action_text = "Verified"
            deal.client.status = 'clear'
        else:
            deal.verification_status = 'rejected'
            action_text = invoice.invoice_status.capitalize()
            if invoice.invoice_status == 'bad_debt':
                deal.client.status = 'bad_debt'

        PaymentApproval.objects.create(deal=deal, payment=payment, approved_by=verifier, approved_remarks=self.faker.sentence(), failure_remarks=None if invoice.invoice_status == 'verified' else "Details did not match.")
        
        deal.save()
        invoice.save()
        deal.client.save()

        ActivityLog.objects.create(deal=deal, message=f"Invoice {invoice.invoice_id} status updated to {invoice.invoice_status}.")
        AuditLogs.objects.create(user=verifier, organization=deal.organization, action=f"Invoice {action_text}", details=f"Invoice {invoice.invoice_id} for deal {deal.deal_id} was {action_text.lower()} by {verifier.username}.")
        Notification.objects.create(recipient=deal.created_by, organization=deal.organization, title=f"Deal {action_text}: {deal.deal_name}", message=f"The deal '{deal.deal_name}' has been {action_text.lower()}.", notification_type='deal_status_changed')
        
        if invoice.invoice_status == 'verified':
            start_of_month = deal.deal_date.replace(day=1)
            end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)
            commission = Commission.objects.create(user=deal.created_by, organization=deal.organization, total_sales=deal.deal_value, commission_rate=Decimal(random.uniform(3.0, 8.0)), start_date=start_of_month, end_date=end_of_month)
            Notification.objects.create(recipient=deal.created_by, organization=deal.organization, title="Commission Generated", message=f"You earned a commission of ${commission.commission_amount:,.2f} for deal {deal.deal_id}.", notification_type='commission_created')