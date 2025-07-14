from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from notifications.models import Notification
from django.utils import timezone
from datetime import timedelta

User = get_user_model()

class Command(BaseCommand):
    help = 'Create test notifications for development'

    def add_arguments(self, parser):
        parser.add_argument(
            '--user-email',
            type=str,
            help='Email of the user to create notifications for',
        )
        parser.add_argument(
            '--count',
            type=int,
            default=5,
            help='Number of test notifications to create',
        )

    def handle(self, *args, **options):
        user_email = options['user_email']
        count = options['count']

        try:
            user = User.objects.get(email=user_email)
        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'User with email {user_email} does not exist')
            )
            return

        # Sample notification data
        notifications_data = [
            {
                'title': 'New Deal Created',
                'message': 'A new deal has been created for Apple Inc. with amount $50,000',
                'notification_type': 'deal_created',
                'priority': 'medium',
                'category': 'business',
                'is_read': False,
            },
            {
                'title': 'Payment Received',
                'message': 'Payment of $25,000 received for deal DEAL-001 from Microsoft Corp',
                'notification_type': 'payment_received',
                'priority': 'high',
                'category': 'business',
                'is_read': False,
            },
            {
                'title': 'New Client Added',
                'message': 'Client "Google LLC" has been added to the system by admin',
                'notification_type': 'client_created',
                'priority': 'medium',
                'category': 'business',
                'is_read': True,
            },
            {
                'title': 'System Maintenance',
                'message': 'Scheduled maintenance will occur tonight at 2:00 AM UTC',
                'notification_type': 'system_alert',
                'priority': 'low',
                'category': 'system',
                'is_read': False,
            },
            {
                'title': 'New User Registration',
                'message': 'New user "John Doe" has been registered with role "Salesperson"',
                'notification_type': 'user_created',
                'priority': 'medium',
                'category': 'user_management',
                'is_read': True,
            },
            {
                'title': 'Commission Updated',
                'message': 'Commission rate has been updated to 5% for all deals',
                'notification_type': 'commission_created',
                'priority': 'high',
                'category': 'business',
                'is_read': False,
            },
            {
                'title': 'Team Assignment',
                'message': 'You have been assigned to the "Sales Team A"',
                'notification_type': 'team_created',
                'priority': 'medium',
                'category': 'user_management',
                'is_read': False,
            },
        ]

        created_count = 0
        for i in range(min(count, len(notifications_data))):
            data = notifications_data[i].copy()
            
            # Create notifications with different timestamps
            created_at = timezone.now() - timedelta(
                hours=i * 2,  # Each notification 2 hours apart
                minutes=i * 15  # Add some minutes variation
            )
            
            notification = Notification.objects.create(
                recipient=user,
                title=data['title'],
                message=data['message'],
                notification_type=data['notification_type'],
                priority=data['priority'],
                category=data['category'],
                is_read=data['is_read'],
                created_at=created_at,
                updated_at=created_at
            )
            
            created_count += 1
            self.stdout.write(
                self.style.SUCCESS(f'Created notification: {notification.title}')
            )

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully created {created_count} test notifications for user {user.email}'
            )
        ) 