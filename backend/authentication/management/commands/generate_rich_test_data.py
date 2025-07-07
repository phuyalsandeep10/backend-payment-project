from django.core.management.base import BaseCommand
from django.db import transaction
from authentication.models import User
from clients.models import Client
from deals.models import Deal, Payment, PaymentInvoice, PaymentApproval
from project.models import Project
from commission.models import Commission
from Verifier_dashboard.models import AuditLogs
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

        if not salespersons or not verifiers:
            self.stdout.write(self.style.ERROR("Key user roles (Salesperson, Verifier) not found. Please run 'initialize_app' first."))
            return

        clients = list(Client.objects.all())
        projects = list(Project.objects.all())

        if not clients or not projects:
            self.stdout.write(self.style.ERROR("Clients or Projects not found. Please run 'initialize_app' first."))
            return
            
        self.create_additional_deals(salespersons, clients, projects, verifiers, 50)
        self.create_guaranteed_recent_data(salespersons[0], clients, projects, verifiers)

        self.stdout.write(self.style.SUCCESS("✅ Rich mock data generation completed successfully!"))

    def create_additional_deals(self, salespersons, clients, projects, verifiers, count):
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating {count} Additional Random Deals ---"))
        for _ in range(count):
            salesperson = random.choice(salespersons)
            # Create deals over the last 4 months to populate charts
            deal_date = self.faker.date_between(start_date='-4M', end_date='-1M')
            self._create_deal_flow(salesperson, clients, projects, verifiers, deal_date)

    def create_guaranteed_recent_data(self, salesperson, clients, projects, verifiers):
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating 5 Guaranteed Recent Deals for {salesperson.username} ---"))
        now = timezone.now()
        # Create deals on consecutive days to build a streak
        for i in range(5):
            # Create deals for the last 5 days
            deal_date = now.date() - timedelta(days=i)
            self._create_deal_flow(salesperson, clients, projects, verifiers, deal_date, is_recent=True, guarantee_verification=True)

    def _create_deal_flow(self, salesperson, clients, projects, verifiers, deal_date, is_recent=False, guarantee_verification=False):
        """Helper function to create a deal and its entire lifecycle."""
        deal = Deal.objects.create(
            organization=salesperson.organization,
            client=random.choice(clients),
            project=random.choice(projects) if projects and random.random() > 0.5 else None,
            deal_name=self.faker.bs().title(),
            deal_value=Decimal(random.randint(15000, 120000)),
            deal_date=deal_date,
            payment_method=random.choice([c[0] for c in Deal.PAYMENT_METHOD_CHOICES]),
            source_type=random.choice([c[0] for c in Deal.SOURCE_TYPES]),
            created_by=salesperson,
        )

        # Process payment and verification
        should_verify = random.random() < 0.85
        if guarantee_verification or should_verify:
            self._process_payment_and_verification(deal, verifiers, guarantee_verification)

    def _process_payment_and_verification(self, deal, verifiers, guarantee_verification=False):
        payment_date = deal.deal_date + timedelta(days=random.randint(1, 10))
        received_amount = deal.deal_value * Decimal(random.uniform(0.6, 1.0))
        payment = Payment.objects.create(
            deal=deal,
            received_amount=received_amount.quantize(Decimal('0.01')),
            payment_date=payment_date,
            payment_type=deal.payment_method
        )
        
        invoice = PaymentInvoice.objects.get(payment=payment)
        verifier = random.choice(verifiers)
        
        # Guarantee verification for streak-building deals
        is_verified = True if guarantee_verification else random.random() < 0.9

        if is_verified:
            invoice.invoice_status = 'verified'
            deal.verification_status = 'verified'
            # Use 'initial payment' or 'full_payment' for streak calculation
            deal.payment_status = 'full_payment' if received_amount == deal.deal_value else 'initial payment'
            action = "Verified"
            
            # Create a corresponding commission record
            if deal.created_by.role and deal.created_by.role.name == 'Salesperson':
                start_of_month = deal.deal_date.replace(day=1)
                end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)
                
                Commission.objects.create(
                    user=deal.created_by,
                    organization=deal.organization,
                    total_sales=deal.deal_value,
                    commission_rate=Decimal(random.uniform(3.5, 8.5)),
                    start_date=start_of_month,
                    end_date=end_of_month,
                    created_by=verifier
                )
        else:
            invoice.invoice_status = 'rejected'
            deal.verification_status = 'rejected'
            action = "Rejected"
        
        invoice.save()
        deal.save()
        
        PaymentApproval.objects.create(
            deal=deal, payment=payment, approved_by=verifier,
            approved_remarks=f"Invoice automatically {action.lower()} by system."
        )
        
        AuditLogs.objects.create(
            organization=deal.organization, user=verifier, action=action,
            details=f"Invoice {invoice.invoice_id} for deal {deal.deal_id} was {action.lower()}."
        ) 