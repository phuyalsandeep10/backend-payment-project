import random
from decimal import Decimal
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import models
from clients.models import Client
from deals.models import Payment, Deal
from authentication.models import User


class Command(BaseCommand):
    help = 'Populate database with sample deals and payments data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing payments before creating new ones',
        )

    def handle(self, *args, **options):
        if options['clear']:
            self.stdout.write('Clearing existing payments...')
            Payment.objects.all().delete()
            self.stdout.write(self.style.SUCCESS('✅ Cleared existing payments'))

        # Get all clients
        clients = list(Client.objects.all())
        if not clients:
            self.stdout.write(self.style.ERROR('❌ No clients found. Please create some clients first.'))
            return

        self.stdout.write(f'Found {len(clients)} clients. Creating payments...')

        # Payment methods to choose from – aligns with Deal.PAYMENT_METHOD_CHOICES keys
        payment_methods = [choice[0] for choice in Deal.PAYMENT_METHOD_CHOICES]

        payments_created = 0

        # Collect potential creators (salespersons) – fallback to any user in same org
        salespersons = list(User.objects.filter(role__name='Salesperson'))

        for client in clients:
            # Decide how many payments (and therefore deals) this client should have (0-3)
            num_payments = random.choices([0, 1, 2, 3], weights=[0.2, 0.4, 0.3, 0.1])[0]

            if num_payments == 0:
                continue

            # Random creator in client's organisation (prefer salesperson)
            org_salespersons = [u for u in salespersons if u.organization == client.organization]
            created_by = random.choice(org_salespersons) if org_salespersons else User.objects.filter(organization=client.organization).first()

            # Basic deal metadata
            deal_value = Decimal(str(random.randint(10000, 500000)))

            deal = Deal.objects.create(
                organization=client.organization,
                client=client,
                project=None,
                created_by=created_by,
                updated_by=created_by,
                payment_status='initial payment',
                source_type=random.choice([c[0] for c in Deal.SOURCE_TYPES]),
                deal_name=f"Auto-deal for {client.client_name}",
                deal_value=deal_value,
                payment_method=random.choice(payment_methods),
            )

            # Create one or more payments linked to this deal
            for idx in range(1, num_payments + 1):
                payment_amount = deal_value if idx == num_payments else deal_value / num_payments

                Payment.objects.create(
                    deal=deal,
                    payment_date=timezone.now() - timedelta(days=random.randint(1, 60)),
                    received_amount=payment_amount,
                    payment_type=random.choice(payment_methods),
                    payment_remarks=f"Seed payment {idx} for deal {deal.deal_id}",
                )

                payments_created += 1

        self.stdout.write(
            self.style.SUCCESS(f'✅ Successfully created {payments_created} payments across {Deal.objects.count()} deals')
        )

        # Show summary
        self.stdout.write('\n📊 Summary:')
        self.stdout.write(f'   Total Clients: {Client.objects.count()}')
        self.stdout.write(f'   Total Deals: {Deal.objects.count()}')
        self.stdout.write(f'   Total Payments: {Payment.objects.count()}') 