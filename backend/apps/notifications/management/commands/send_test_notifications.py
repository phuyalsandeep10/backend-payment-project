from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from apps.notifications.models import Notification
from apps.organization.models import Organization
from apps.notifications.services import NotificationService

User = get_user_model()

class Command(BaseCommand):
    help = 'Send test notifications to a user for testing the real-time notification system'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            help='Email of the user to send notifications to',
            default='shishirkafle84@gmail.com'
        )
        parser.add_argument(
            '--count',
            type=int,
            help='Number of test notifications to send',
            default=3
        )

    def handle(self, *args, **options):
        email = options['email']
        count = options['count']

        try:
            user = User.objects.get(email=email)
            self.stdout.write(f"📧 Found user: {user.email} (ID: {user.id})")
            
            # Get user's organization if available
            organization = None
            if hasattr(user, 'organization') and user.organization:
                organization = user.organization
                self.stdout.write(f"🏢 User organization: {organization.name}")

            # Test notification data
            test_notifications = [
                {
                    'title': '🎉 Welcome to the Notification System!',
                    'message': 'This is a test notification to verify real-time WebSocket connectivity.',
                    'notification_type': 'test_notification',
                    'priority': 'high',
                    'category': 'system',
                    'action_url': '/dashboard'
                },
                {
                    'title': '💼 New Deal Created',
                    'message': 'A new deal "Enterprise Software License" worth $50,000 has been created and assigned to your team.',
                    'notification_type': 'deal_created',
                    'priority': 'medium',
                    'category': 'business',
                    'related_object_type': 'deal',
                    'related_object_id': 123,
                    'action_url': '/deals/123'
                },
                {
                    'title': '💰 Payment Received',
                    'message': 'Payment of $25,000 has been received for deal "Enterprise Software License". Commission calculation in progress.',
                    'notification_type': 'payment_received',
                    'priority': 'high',
                    'category': 'business',
                    'related_object_type': 'payment',
                    'related_object_id': 456,
                    'action_url': '/payments/456'
                },
                {
                    'title': '👥 New Client Onboarded',
                    'message': 'Client "TechCorp Solutions" has been successfully onboarded to your organization. Welcome them to the system!',
                    'notification_type': 'client_created',
                    'priority': 'medium',
                    'category': 'business',
                    'related_object_type': 'client',
                    'related_object_id': 789,
                    'action_url': '/clients/789'
                },
                {
                    'title': '🔔 System Alert',
                    'message': 'Your monthly commission report is ready for review. Please check the commission dashboard for detailed information.',
                    'notification_type': 'system_alert',
                    'priority': 'low',
                    'category': 'system',
                    'action_url': '/commission-report'
                }
            ]

            notifications_sent = 0
            service = NotificationService()

            for i in range(min(count, len(test_notifications))):
                notification_data = test_notifications[i % len(test_notifications)]
                
                # Create notification using the service (this should trigger real-time broadcast)
                notifications = service.create_notification(
                    notification_type=notification_data['notification_type'],
                    title=notification_data['title'],
                    message=notification_data['message'],
                    recipient=user,
                    organization=organization,
                    priority=notification_data['priority'],
                    category=notification_data['category'],
                    related_object_type=notification_data.get('related_object_type'),
                    related_object_id=notification_data.get('related_object_id'),
                    action_url=notification_data.get('action_url')
                )
                
                notifications_sent += 1
                notification_title = notifications[0].title if notifications else notification_data['title']
                self.stdout.write(
                    self.style.SUCCESS(f"✅ Sent notification {i+1}: {notification_title}")
                )

            self.stdout.write(
                self.style.SUCCESS(
                    f"\n🎯 Successfully sent {notifications_sent} test notifications to {user.email}"
                )
            )
            self.stdout.write(
                self.style.WARNING(
                    "💡 Check your frontend WebSocket connection to see real-time notifications!"
                )
            )

        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f"❌ User with email {email} not found")
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"❌ Error sending notifications: {str(e)}")
            )