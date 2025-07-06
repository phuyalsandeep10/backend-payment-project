from django.core.management.base import BaseCommand
from django.db import transaction
from authentication.models import User
from clients.models import Client
from deals.models import Deal, Payment, ActivityLog
from project.models import Project
from commission.models import Commission
from notifications.models import Notification, NotificationTemplate
from team.models import Team
from datetime import datetime, timedelta
from decimal import Decimal
import random
from faker import Faker
from django.db.models import Sum
from django.utils import timezone

class Command(BaseCommand):
    help = 'Generates a rich and varied dataset for all key user roles.'

    @transaction.atomic
    def handle(self, *args, **options):
        self.faker = Faker()
        self.stdout.write(self.style.HTTP_INFO("--- Generating Rich & Varied Mock Data ---"))

        # Get key users to generate data for
        salespersons = list(User.objects.filter(role__name__icontains='Salesperson'))
        verifiers = list(User.objects.filter(role__name__icontains='Verifier'))
        org_admins = list(User.objects.filter(role__name__icontains='Organization Admin'))

        if not all([salespersons, verifiers, org_admins]):
            self.stdout.write(self.style.ERROR("Key user roles not found. Please run 'initialize_app' first."))
            return

        # 1. Create Clients owned by salespersons
        clients = self.create_clients(salespersons)

        # 2. Create Projects linked to clients and salespersons
        projects = self.create_projects(clients, salespersons)

        # 3. Create a rich set of deals across different time periods
        deals = self.create_all_deals(salespersons, clients, projects, verifiers)
        
        # 4. Create Payments for those deals
        self.create_payments_for_deals(deals)

        # 5. Create Commissions based on verified deals
        self.create_commissions(salespersons, org_admins)

        # 6. Create Teams
        self.create_teams(salespersons)
        
        # 7. Create Notifications
        self.create_notifications(deals)

        self.stdout.write(self.style.SUCCESS("✅ Rich mock data generated successfully!"))

    def create_clients(self, salespersons):
        self.stdout.write(self.style.HTTP_INFO("  - Creating Clients..."))
        clients = []
        for _ in range(50):  # Create more clients
            clients.append(Client.objects.create(
                organization=salespersons[0].organization,
                client_name=self.faker.company(),
                email=self.faker.unique.email(),
                phone_number=self.faker.phone_number(),
                nationality=self.faker.country(),
                created_by=random.choice(salespersons)
            ))
        self.stdout.write(self.style.SUCCESS(f"    - Created {len(clients)} clients."))
        return clients

    def create_projects(self, clients, salespersons):
        self.stdout.write(self.style.HTTP_INFO("  - Creating Projects..."))
        projects = []
        for client in random.sample(clients, 20): # Projects for a subset of clients
            projects.append(Project.objects.create(
                name=f"{client.client_name} - {self.faker.bs()}",
                description=self.faker.text(max_nb_chars=250),
                status=random.choice(['pending', 'in_progress', 'completed']),
                created_by=random.choice(salespersons)
            ))
        self.stdout.write(self.style.SUCCESS(f"    - Created {len(projects)} projects."))
        return projects

    def create_all_deals(self, salespersons, clients, projects, verifiers):
        self.stdout.write(self.style.HTTP_INFO("  - Creating Deals across all time periods..."))
        all_deals = []
        for salesperson in salespersons:
            # More deals for salesperson1 for predictable testing
            deal_count = 100 if salesperson.username == 'salesperson1' else 40
            
            for _ in range(deal_count):
                deal_date = self.faker.date_time_between(start_date='-2y', end_date='now', tzinfo=None).date()
                created_at = self.faker.date_time_between(start_date=deal_date, end_date=timezone.now())
                
                deal = self.create_single_deal(salesperson, clients, projects, verifiers, deal_date)
                deal.deal_name = self.faker.bs().title()
                deal.created_at = created_at
                deal.save()
                all_deals.append(deal)

        self.stdout.write(self.style.SUCCESS(f"    - Created a total of {len(all_deals)} deals."))
        return all_deals

    def create_single_deal(self, user, clients, projects, verifiers, deal_date):
        # Define realistic status flows
        verification_status = random.choices(['pending', 'verified', 'rejected'], weights=[0.2, 0.7, 0.1], k=1)[0]
        
        if verification_status == 'verified':
            payment_status = random.choices(['pending', 'partial_payment', 'full_payment'], weights=[0.2, 0.4, 0.4], k=1)[0]
        elif verification_status == 'rejected':
            payment_status = 'pending' # Rejected deals can't have payments
        else: # pending verification
            payment_status = 'pending'

        deal = Deal.objects.create(
            organization=user.organization,
            client=random.choice(clients),
            project=random.choice(projects) if projects and random.random() > 0.5 else None,
            deal_name=self.faker.bs().title(),
            deal_value=Decimal(random.randint(5000, 150000)),
            currency=random.choice(['USD', 'EUR', 'GBP']),
            deal_date=deal_date,
            due_date=deal_date + timedelta(days=random.randint(15, 90)),
            payment_status=payment_status,
            verification_status=verification_status,
            source_type=random.choice(['linkedin', 'referral', 'google']),
            payment_method=random.choice(['wallet', 'bank', 'cash']),
            created_by=user,
            deal_remarks=self.faker.sentence()
        )
        
        # Log creation
        ActivityLog.objects.create(deal=deal, message=f"Deal created by {user.username}.")
        
        # Simulate verification action
        if deal.verification_status in ['verified', 'rejected']:
            verifier = random.choice(verifiers)
            deal.updated_by = verifier
            deal.save()
            ActivityLog.objects.create(deal=deal, message=f"Deal {deal.verification_status} by {verifier.username}.")

        return deal

    def create_payments_for_deals(self, deals):
        self.stdout.write(self.style.HTTP_INFO("  - Creating Payments for deals..."))
        payment_count = 0
        for deal in deals:
            # Skip payments for rejected deals or deals with no payment
            if deal.verification_status == 'rejected' or deal.payment_status == 'pending':
                continue

            payment_date = deal.deal_date + timedelta(days=random.randint(1, 20))
            if deal.payment_status == 'full_payment':
                Payment.objects.create(
                    deal=deal,
                    received_amount=deal.deal_value,
                    payment_date=payment_date,
                    payment_type=deal.payment_method,
                    payment_remarks="Full payment received."
                )
                payment_count += 1
            elif deal.payment_status == 'partial_payment':
                Payment.objects.create(
                    deal=deal,
                    received_amount=deal.deal_value * Decimal(random.uniform(0.2, 0.7)),
                    payment_date=payment_date,
                    payment_type=deal.payment_method,
                    payment_remarks="Partial payment received."
                )
                payment_count += 1
        self.stdout.write(self.style.SUCCESS(f"    - Created {payment_count} payments."))

    def create_commissions(self, salespersons, org_admins):
        self.stdout.write(self.style.HTTP_INFO("  - Creating Commissions..."))
        commission_count = 0
        for user in salespersons:
            total_sales = Deal.objects.filter(
                created_by=user, 
                verification_status='verified'
            ).aggregate(total_sales=Sum('deal_value'))['total_sales'] or Decimal('0.00')

            if total_sales > 0:
                Commission.objects.create(
                    user=user,
                    organization=user.organization,
                    total_sales=total_sales,
                    commission_rate=Decimal(random.uniform(3, 8)),
                    bonus=total_sales * Decimal(random.uniform(0.01, 0.03)),
                    start_date=datetime.now().date().replace(day=1),
                    end_date=datetime.now().date(),
                    created_by=random.choice(org_admins)
                )
                commission_count += 1
        self.stdout.write(self.style.SUCCESS(f"    - Created {commission_count} commission records."))

    def create_teams(self, salespersons):
        self.stdout.write(self.style.HTTP_INFO("  - Creating Teams..."))
        if not salespersons: return
        
        team_alpha = Team.objects.create(name="Alpha Team", organization=salespersons[0].organization)
        team_alpha.members.set(salespersons[:len(salespersons)//2])
        
        team_beta = Team.objects.create(name="Beta Team", organization=salespersons[0].organization)
        team_beta.members.set(salespersons[len(salespersons)//2:])
        self.stdout.write(self.style.SUCCESS("    - Created Alpha and Beta teams."))

    def create_notifications(self, deals):
        self.stdout.write(self.style.HTTP_INFO("  - Creating Notifications..."))
        # Simplified notification creation
        verified_deals = [d for d in deals if d.verification_status == 'verified']
        notification_count = 0
        for deal in random.sample(verified_deals, min(len(verified_deals), 10)):
            Notification.objects.create(
                recipient=deal.created_by,
                title=f"Deal Verified: {deal.deal_id}",
                message=f"Congratulations! Your deal for {deal.client.client_name} has been verified.",
                notification_type='deal_verified'
            )
            notification_count += 1
        self.stdout.write(self.style.SUCCESS(f"    - Created {notification_count} notifications.")) 