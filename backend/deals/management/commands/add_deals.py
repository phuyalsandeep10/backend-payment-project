import random
from datetime import date, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from clients.models import Client
from deals.models import Deal
from authentication.models import User
from decimal import Decimal

class Command(BaseCommand):
    help = 'Creates sample deals for clients created by a specific salesperson.'

    def add_arguments(self, parser):
        parser.add_argument('user_id', type=int, help='The ID of the salesperson to create deals for.')
        parser.add_argument('--count', type=int, default=3, help='The number of deals to create per client.')

    @transaction.atomic
    def handle(self, *args, **options):
        user_id = options['user_id']
        deal_count_per_client = options['count']

        try:
            salesperson = User.objects.get(pk=user_id)
            self.stdout.write(self.style.SUCCESS(f"Found salesperson: '{salesperson.email}'"))
        except User.DoesNotExist:
            raise CommandError(f"User with ID '{user_id}' does not exist.")

        clients = Client.objects.filter(created_by=salesperson)
        if not clients.exists():
            self.stdout.write(self.style.WARNING(f"No clients found for salesperson '{salesperson.email}'. No deals will be created."))
            return

        self.stdout.write(self.style.NOTICE(f"Found {clients.count()} clients. Creating {deal_count_per_client} deals for each..."))

        deals_created_total = 0
        today = date.today()

        for client in clients:
            for i in range(deal_count_per_client):
                deal_date = today - timedelta(days=random.randint(0, 90))
                due_date = deal_date + timedelta(days=random.randint(15, 60))
                deal_value = Decimal(random.randrange(5000, 100000))
                deal_status = random.choice(['pending', 'won', 'lost'])
                pay_status = 'pending'
                if deal_status == 'won':
                    pay_status = random.choice(['pending', 'partial', 'verified', 'rejected'])

                deal = Deal.objects.create(
                    client_name=client.client_name,
                    deal_value=deal_value,
                    deal_date=deal_date,
                    due_date=due_date,
                    deal_status=deal_status,
                    pay_status=pay_status,
                    created_by=salesperson,
                    organization=salesperson.organization
                )
                deals_created_total += 1
                self.stdout.write(f"  - Created Deal for '{client.client_name}' with value {deal_value}")

        self.stdout.write("--------------------")
        self.stdout.write(self.style.SUCCESS(f"Script finished."))
        self.stdout.write(f"Total deals created: {deals_created_total}") 