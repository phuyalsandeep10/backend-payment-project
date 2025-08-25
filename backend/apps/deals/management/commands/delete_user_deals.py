"""
Management command to delete deals created by a specific user
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from apps.deals.models import Deal, Payment
from django.db import transaction

User = get_user_model()


class Command(BaseCommand):
    help = 'Delete all deals created by a specific user'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            required=True,
            help='Email of the user whose deals should be deleted'
        )
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm the deletion (required for safety)'
        )

    def handle(self, *args, **options):
        email = options['email']
        confirm = options['confirm']
        
        if not confirm:
            self.stdout.write(
                self.style.WARNING(
                    'This command will permanently delete deals and related data. '
                    'Use --confirm flag to proceed.'
                )
            )
            return
        
        try:
            # Find the user
            user = User.objects.get(email=email)
            self.stdout.write(f"Found user: {user.email} ({user.first_name} {user.last_name})")
            
            # Find deals created by this user
            deals = Deal.objects.filter(created_by=user)
            deal_count = deals.count()
            
            if deal_count == 0:
                self.stdout.write(
                    self.style.SUCCESS(f"No deals found for user {email}")
                )
                return
            
            self.stdout.write(f"Found {deal_count} deals created by {email}")
            
            # Show deal details
            for deal in deals:
                self.stdout.write(f"  - Deal ID: {deal.deal_id}, Name: {deal.deal_name}, Value: {deal.deal_value}")
                
                # Count related payments
                payment_count = Payment.objects.filter(deal=deal).count()
                if payment_count > 0:
                    self.stdout.write(f"    └─ {payment_count} related payments")
            
            # Confirm deletion
            self.stdout.write(
                self.style.WARNING(
                    f"\nThis will delete {deal_count} deals and all related data (payments, activity logs, etc.)"
                )
            )
            
            # Perform deletion in a transaction
            with transaction.atomic():
                # Delete deals (this will cascade to related objects)
                deleted_count, deleted_objects = deals.delete()
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Successfully deleted {deal_count} deals and {deleted_count} total objects"
                    )
                )
                
                # Show what was deleted
                for model, count in deleted_objects.items():
                    if count > 0:
                        self.stdout.write(f"  - {model}: {count} objects")
                        
        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f"User with email {email} not found")
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Error deleting deals: {str(e)}")
            )