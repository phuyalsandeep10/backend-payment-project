from django.core.management.base import BaseCommand
from django.db import transaction
from authentication.models import User
from clients.models import Client
from deals.models import Deal, Payment
from datetime import datetime, timedelta
from decimal import Decimal
import random
from faker import Faker

fake = Faker()

class Command(BaseCommand):
    help = 'Generates a rich and varied dataset for dashboard testing across multiple time periods.'

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("--- Generating Rich Dashboard Mock Data ---"))

        manager_user = User.objects.filter(username='salesmanager').first()
        if not manager_user:
            self.stdout.write(self.style.ERROR("Sales Manager user not found. Please run 'initialize_app' first."))
            return

        clients = Client.objects.all()
        if clients.count() < 5:
            self.stdout.write(self.style.ERROR("Not enough clients found. Please run 'initialize_app' first."))
            return

        # Clean up old test data to prevent bloat
        Deal.objects.filter(deal_remarks__icontains='dashboard testing').delete()
        self.stdout.write(self.style.SUCCESS("🧹 Cleaned up old dashboard test deals."))

        # Create varied data
        self.create_deals_for_period(manager_user, clients, 'daily')
        self.create_deals_for_period(manager_user, clients, 'weekly')
        self.create_deals_for_period(manager_user, clients, 'monthly')
        self.create_deals_for_period(manager_user, clients, 'yearly')

        self.stdout.write(self.style.SUCCESS("✅ Rich dashboard mock data generated successfully!"))

    def create_deals_for_period(self, user, clients, period):
        self.stdout.write(f"  - Creating deals for period: {period}")
        today = datetime.now().date()
        deals_created = 0

        if period == 'daily':
            # 3-5 deals for today
            for _ in range(random.randint(3, 5)):
                self.create_single_deal(user, clients, today)
                deals_created += 1
        
        elif period == 'weekly':
            # 2-4 deals per day for the last 7 days
            for i in range(7):
                date = today - timedelta(days=i)
                for _ in range(random.randint(2, 4)):
                    self.create_single_deal(user, clients, date)
                    deals_created += 1

        elif period == 'monthly':
            # 1-3 deals every other day for the last 30 days
            for i in range(0, 30, 2):
                date = today - timedelta(days=i)
                for _ in range(random.randint(1, 3)):
                    self.create_single_deal(user, clients, date)
                    deals_created += 1
        
        elif period == 'yearly':
            # 5-10 deals per month for the last 12 months
            for i in range(12):
                # Get a random day in the month
                month_date = today - timedelta(days=i * 30)
                date = month_date.replace(day=random.randint(1, 28))
                for _ in range(random.randint(5, 10)):
                    self.create_single_deal(user, clients, date)
                    deals_created += 1
        
        self.stdout.write(self.style.SUCCESS(f"    - Created {deals_created} deals for {period} view."))

    def create_single_deal(self, user, clients, deal_date):
        client = random.choice(list(clients))
        deal_value = Decimal(random.randint(1000, 75000))
        payment_status = random.choice(['pending', 'verified', 'partial', 'rejected'])
        
        deal = Deal.objects.create(
            organization=user.organization,
            client=client,
            deal_value=deal_value,
            deal_date=deal_date,
            due_date=deal_date + timedelta(days=random.randint(30, 90)),
            payment_status=payment_status,
            verification_status=random.choice(['pending', 'verified', 'rejected']),
            client_status=random.choice(['interested', 'not_interested', 'follow_up']),
            source_type=random.choice(['referral', 'direct', 'marketing', 'social_media']),
            payment_method=random.choice(['cash', 'bank_transfer', 'cheque', 'online']),
            deal_remarks=f"Rich dashboard testing deal created on {datetime.now()}",
            created_by=user,
        )

        # Create payments for verified or partial deals
        if payment_status in ['verified', 'partial']:
            self.create_payments_for_deal(deal)

    def create_payments_for_deal(self, deal):
        payment_count = 1 if deal.payment_status == 'verified' else random.randint(1, 3)
        
        for i in range(payment_count):
            amount_multiplier = 1 if deal.payment_status == 'verified' else (i + 1) * 0.25
            
            Payment.objects.create(
                deal=deal,
                payment_date=deal.deal_date + timedelta(days=random.randint(1, 10)),
                received_amount=deal.deal_value * Decimal(amount_multiplier),
                payment_type=random.choice(Payment.PAYMENT_TYPE)[0],
                payment_remarks=f"Payment for dashboard testing deal."
            ) 