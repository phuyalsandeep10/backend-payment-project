from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from faker import Faker
from decimal import Decimal
import random
from datetime import timedelta

from authentication.models import User
from clients.models import Client
from deals.models import Deal, Payment, PaymentInvoice, PaymentApproval, ActivityLog
from project.models import Project
from commission.models import Commission
from Verifier_dashboard.models import AuditLogs
from notifications.models import Notification

class Command(BaseCommand):
    help = 'Generates additional rich and varied test data on top of existing data.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--deals',
            type=int,
            default=50,
            help='Number of additional deals to create (default: 50)'
        )
        parser.add_argument(
            '--clients',
            type=int,
            default=10,
            help='Number of additional clients to create (default: 10)'
        )
        parser.add_argument(
            '--projects',
            type=int,
            default=5,
            help='Number of additional projects to create (default: 5)'
        )

    @transaction.atomic
    def handle(self, *args, **options):
        self.faker = Faker()
        self.stdout.write(self.style.HTTP_INFO("--- Generating Rich & Varied Test Data ---"))

        # Get existing data
        salespersons = list(User.objects.filter(role__name__icontains='Salesperson'))
        verifiers = list(User.objects.filter(role__name__icontains='Verifier'))
        clients = list(Client.objects.all())
        projects = list(Project.objects.all())

        if not salespersons:
            self.stdout.write(self.style.ERROR("❌ No salespersons found. Please run 'initialize_app' first."))
            return

        if not clients:
            self.stdout.write(self.style.ERROR("❌ No clients found. Please run 'initialize_app' first."))
            return

        # Create additional data
        self.create_additional_clients(clients[0].organization, salespersons, options['clients'])
        self.create_additional_projects(salespersons, options['projects'])
        self.create_additional_deals(salespersons, clients, projects, verifiers, options['deals'])
        self.create_guaranteed_recent_data(salespersons[0], clients, projects, verifiers)

        self.stdout.write(self.style.SUCCESS("✅ Rich test data generation completed successfully!"))

    def create_additional_clients(self, organization, salespersons, count):
        """Create additional clients."""
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating {count} Additional Clients ---"))
        
        for i in range(count):
            client = Client.objects.create(
                organization=organization,
                client_name=f"{self.faker.company()} {self.faker.company_suffix()}",
                email=self.faker.unique.email(),
                phone_number=self.faker.phone_number(),
                created_by=random.choice(salespersons),
                satisfaction=random.choice(['neutral', 'satisfied', 'unsatisfied']),
                status='new'  # Start with 'new' status, will be updated by deal verification
            )
            
            self.stdout.write(f"  - Created client: {client.client_name}")
        
        self.stdout.write(self.style.SUCCESS(f"✅ Created {count} additional clients."))

    def create_additional_projects(self, salespersons, count):
        """Create additional projects."""
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating {count} Additional Projects ---"))
        
        for i in range(count):
            project = Project.objects.create(
                name=self.faker.catch_phrase(),
                description=f"{self.faker.catch_phrase()}. {self.faker.text(max_nb_chars=200)}",
                created_by=random.choice(salespersons)
            )
            
            self.stdout.write(f"  - Created project: {project.name}")
        
        self.stdout.write(self.style.SUCCESS(f"✅ Created {count} additional projects."))

    def create_additional_deals(self, salespersons, clients, projects, verifiers, count):
        """Create additional deals with varied scenarios."""
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating {count} Additional Deals ---"))
        
        scenarios = [
            'verified_full', 'verified_partial', 'multi_partial', 
            'rejected', 'refunded', 'bad_debt', 'pending_verification',
            'verified_full', 'verified_partial'  # Higher weight for verified scenarios
        ]
        
        for i in range(count):
            salesperson = random.choice(salespersons)
            deal_date = self.faker.date_between(start_date='-4M', end_date='-1M')
            
            deal = Deal.objects.create(
                organization=salesperson.organization,
                client=random.choice(clients),
                project=random.choice(projects) if projects and random.random() > 0.3 else None,
                deal_name=self.faker.bs().title(),
                deal_value=Decimal(random.randint(500, 50000)),
                deal_date=deal_date,
                payment_method=random.choice([c[0] for c in Deal.PAYMENT_METHOD_CHOICES]),
                source_type=random.choice([c[0] for c in Deal.SOURCE_TYPES]),
                created_by=salesperson,
            )
            
            # Create activity log
            ActivityLog.objects.create(
                deal=deal, 
                message=f"Deal '{deal.deal_name}' created by {deal.created_by.username} for {deal.client.client_name}."
            )
            
            # Process payment and verification if verifiers exist
            if verifiers:
                scenario = random.choice(scenarios)
                self.process_deal_payment_and_verification(deal, verifiers, scenario)
            
            if (i + 1) % 10 == 0:
                self.stdout.write(f"  - Created {i + 1} deals...")
        
        self.stdout.write(self.style.SUCCESS(f"✅ Created {count} additional deals."))

    def create_guaranteed_recent_data(self, salesperson, clients, projects, verifiers):
        """Create guaranteed recent deals for streak building."""
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating Recent Deals for {salesperson.username} ---"))
        
        today = timezone.now().date()
        for i in range(5):
            deal_date = today - timedelta(days=i)
            
            deal = Deal.objects.create(
                organization=salesperson.organization,
                client=random.choice(clients),
                project=random.choice(projects) if projects and random.random() > 0.5 else None,
                deal_name=f"Recent Deal Day {i+1}",
                deal_value=Decimal(random.randint(200, 5000)),
                deal_date=deal_date,
                payment_method='bank',
                source_type='referral',
                created_by=salesperson,
                payment_status='initial payment'
            )
            
            # Create activity log
            ActivityLog.objects.create(
                deal=deal, 
                message=f"Recent deal '{deal.deal_name}' created by {deal.created_by.username} for {deal.client.client_name}."
            )
            
            # Process payment if verifiers exist
            if verifiers:
                self.create_payment_flow(deal, deal.deal_value, deal_date, random.choice(verifiers), 'verified_full')
        
        self.stdout.write(self.style.SUCCESS(f"✅ Created 5 recent deals for {salesperson.username}."))

    def process_deal_payment_and_verification(self, deal, verifiers, scenario):
        """Process payment and verification for a deal."""
        verifier = random.choice(verifiers)
        payment_date = deal.deal_date + timedelta(days=random.randint(1, 10))
        
        if scenario == 'multi_partial':
            # Create multiple partial payments
            remaining_value = deal.deal_value
            for i in range(random.randint(2, 4)):
                if remaining_value <= 0:
                    break
                payment_amount = (remaining_value / 2) * Decimal(random.uniform(0.5, 0.9))
                self.create_payment_flow(deal, payment_amount, payment_date + timedelta(days=i*10), verifier, 'verified' if i < 2 else 'pending')
                remaining_value -= payment_amount
            return

        # Single payment scenario
        if scenario == 'verified_full':
            payment_amount = deal.deal_value * Decimal(random.uniform(0.9, 1.0))
        elif scenario == 'verified_partial':
            payment_amount = deal.deal_value * Decimal(random.uniform(0.5, 0.8))
        else:
            payment_amount = deal.deal_value * Decimal(random.uniform(0.3, 0.7))
        
        self.create_payment_flow(deal, payment_amount, payment_date, verifier, scenario)

    def create_payment_flow(self, deal, amount, payment_date, verifier, final_status):
        """Create complete payment flow for a deal."""
        # Create payment
        payment = Payment.objects.create(
            deal=deal,
            received_amount=amount.quantize(Decimal('0.01')),
            payment_date=payment_date,
            payment_type=deal.payment_method
        )
        
        # Get invoice (created automatically via signal)
        invoice = PaymentInvoice.objects.get(payment=payment)
        
        # Map status
        status_map = {
            'verified_full': 'verified',
            'verified_partial': 'verified',
            'rejected': 'rejected',
            'refunded': 'refunded',
            'bad_debt': 'bad_debt',
            'pending_verification': 'pending'
        }
        invoice.invoice_status = status_map.get(final_status, 'pending')
        
        # Update deal and client status
        if invoice.invoice_status == 'verified':
            deal.verification_status = 'verified'
            deal.payment_status = 'full_payment' if amount >= deal.deal_value else 'initial payment'
            action_text = "Verified"
            deal.client.status = 'clear'
        else:
            deal.verification_status = 'rejected' if invoice.invoice_status in ['rejected', 'bad_debt'] else 'pending'
            action_text = invoice.invoice_status.capitalize()
            if invoice.invoice_status == 'bad_debt':
                deal.client.status = 'bad_debt'

        # Create payment approval
        PaymentApproval.objects.create(
            deal=deal,
            payment=payment,
            approved_by=verifier,
            verifier_remarks=self.faker.sentence(),
            failure_remarks=None if invoice.invoice_status == 'verified' else "Details did not match."
        )
        
        # Save changes
        deal.save()
        invoice.save()
        deal.client.save()

        # Create activity log
        ActivityLog.objects.create(
            deal=deal,
            message=f"Invoice {invoice.invoice_id} status updated to {invoice.invoice_status}."
        )
        
        # Create audit log
        AuditLogs.objects.create(
            user=verifier,
            organization=deal.organization,
            action=f"Invoice {action_text}",
            details=f"Invoice {invoice.invoice_id} for deal {deal.deal_id} was {action_text.lower()} by {verifier.username}."
        )
        
        # Create notification
        Notification.objects.create(
            recipient=deal.created_by,
            organization=deal.organization,
            title=f"Deal {action_text}: {deal.deal_name}",
            message=f"The deal '{deal.deal_name}' has been {action_text.lower()}.",
            notification_type='deal_status_changed'
        )
        
        # Create commission if verified
        if invoice.invoice_status == 'verified':
            start_of_month = deal.deal_date.replace(day=1)
            end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)
            
            commission = Commission.objects.create(
                user=deal.created_by,
                organization=deal.organization,
                total_sales=deal.deal_value,
                commission_rate=Decimal(random.uniform(3.0, 8.0)),
                start_date=start_of_month,
                end_date=end_of_month
            )
            
            Notification.objects.create(
                recipient=deal.created_by,
                organization=deal.organization,
                title="Commission Generated",
                message=f"You earned a commission of ${commission.commission_amount:,.2f} for deal {deal.deal_id}.",
                notification_type='commission_created'
            )