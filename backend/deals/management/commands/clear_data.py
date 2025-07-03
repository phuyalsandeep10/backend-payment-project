from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from clients.models import Client
from deals.models import Deal, Payment
from commission.models import Commission

class Command(BaseCommand):
    help = 'Deletes specified data from the database. USE WITH CAUTION.'

    def add_arguments(self, parser):
        parser.add_argument('--clients', action='store_true', help='Delete all Client data.')
        parser.add_argument('--deals', action='store_true', help='Delete all Deal, Payment, and Commission data.')
        parser.add_argument('--all', action='store_true', help='Delete all supported data (clients and deals).')
        parser.add_argument('--confirm', action='store_true', help='Bypass interactive confirmation.')

    @transaction.atomic
    def handle(self, *args, **options):
        delete_clients = options['clients'] or options['all']
        delete_deals = options['deals'] or options['all']

        if not (delete_clients or delete_deals):
            self.stdout.write(self.style.WARNING('No data type specified to delete. Use --clients, --deals, or --all.'))
            return

        if not options['confirm']:
            self.stdout.write(self.style.WARNING('This command will permanently delete data from your database.'))
            confirmation = input('Are you sure you want to continue? (yes/no): ')
            if confirmation.lower() != 'yes':
                self.stdout.write(self.style.ERROR('Operation cancelled.'))
                return

        if delete_deals:
            self.stdout.write('Deleting Deal, Payment, and Commission data...')
            commission_count, _ = Commission.objects.all().delete()
            payment_count, _ = Payment.objects.all().delete()
            deal_count, _ = Deal.objects.all().delete()
            self.stdout.write(self.style.SUCCESS(f'Deleted {deal_count} deals, {payment_count} payments, and {commission_count} commissions.'))

        if delete_clients:
            self.stdout.write('Deleting Client data...')
            client_count, _ = Client.objects.all().delete()
            self.stdout.write(self.style.SUCCESS(f'Deleted {client_count} clients.'))

        self.stdout.write(self.style.SUCCESS('Data clearing process finished.')) 