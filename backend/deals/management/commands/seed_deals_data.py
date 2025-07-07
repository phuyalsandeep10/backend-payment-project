import random
from decimal import Decimal
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import models
from clients.models import Client
from deals.models import Payment


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

        # Payment methods to choose from
        payment_methods = ['Mobile Wallet', 'Bank Transfer', 'QR Payment', 'Credit Card', 'Cash']
        
        # Status choices
        statuses = ['pending', 'verified', 'rejected']
        status_weights = [0.3, 0.6, 0.1]  # More verified than pending or rejected

        payments_created = 0

        for client in clients:
            # Decide how many payments this client should have (0-3)
            num_payments = random.choices([0, 1, 2, 3], weights=[0.2, 0.4, 0.3, 0.1])[0]
            
            if num_payments == 0:
                continue

            # Update client with deal-like information
            client.value = Decimal(str(random.randint(10000, 500000)))
            client.expected_close = (timezone.now() + timedelta(days=random.randint(30, 180))).date()
            client.last_contact = timezone.now() - timedelta(days=random.randint(1, 30))
            
            # Set some deal remarks
            remarks_options = [
                f"High-value client for {client.client_name}",
                f"Software development project for {client.client_name}",
                f"Website redesign and maintenance contract",
                f"Mobile app development deal",
                f"E-commerce platform development",
                f"Digital marketing services contract",
                f"Custom ERP system development",
                None
            ]
            client.remarks = random.choice(remarks_options)
            client.save()

            for sequence in range(1, num_payments + 1):
                # Create payment
                payment_date = timezone.now() - timedelta(days=random.randint(1, 60))
                
                # Payment amount (make first payment larger usually)
                if sequence == 1:
                    max_amount = int(client.value * Decimal('0.7'))
                    amount = Decimal(str(random.randint(5000, max_amount)))
                else:
                    remaining = client.value - (Payment.objects.filter(client=client, sequence_number__lt=sequence).aggregate(
                        total=models.Sum('amount'))['total'] or Decimal('0'))
                    max_remaining = min(50000, int(remaining))
                    amount = Decimal(str(random.randint(1000, max(1000, max_remaining))))

                payment = Payment.objects.create(
                    client=client,
                    sequence_number=sequence,
                    amount=amount,
                    currency='NPR',
                    payment_method=random.choice(payment_methods),
                    status=random.choices(statuses, weights=status_weights)[0],
                    created_at=payment_date,
                )

                # If verified, set verification details
                if payment.status == 'verified':
                    payment.verified_at = payment_date + timedelta(hours=random.randint(1, 48))
                    # You could set verified_by to a random verifier user if needed
                    payment.save()

                payments_created += 1

        self.stdout.write(
            self.style.SUCCESS(f'✅ Successfully created {payments_created} payments for {len([c for c in clients if c.payments.exists()])} clients')
        )

        # Show summary
        self.stdout.write('\n📊 Summary:')
        self.stdout.write(f'   Total Clients: {Client.objects.count()}')
        self.stdout.write(f'   Clients with Payments: {Client.objects.filter(payments__isnull=False).distinct().count()}')
        self.stdout.write(f'   Total Payments: {Payment.objects.count()}')
        self.stdout.write(f'   Pending Payments: {Payment.objects.filter(status="pending").count()}')
        self.stdout.write(f'   Verified Payments: {Payment.objects.filter(status="verified").count()}')
        self.stdout.write(f'   Rejected Payments: {Payment.objects.filter(status="rejected").count()}') 