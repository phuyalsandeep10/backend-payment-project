from django.core.management.base import BaseCommand
from deals.models import Deal, Payment

class Command(BaseCommand):
    help = 'Check deals and payments in the database'

    def handle(self, *args, **options):
        deals = Deal.objects.all()
        self.stdout.write(f"Total deals: {deals.count()}")
        
        for deal in deals:
            payments = deal.payments.all()
            self.stdout.write(f"Deal {deal.deal_id}: {payments.count()} payments")
            if payments.count() > 0:
                for payment in payments:
                    self.stdout.write(f"  - Payment {payment.id}: ${payment.received_amount} on {payment.payment_date}")
        
        total_payments = Payment.objects.count()
        self.stdout.write(f"Total payments in database: {total_payments}") 