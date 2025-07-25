"""
Management command to test the enhanced notification group system
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from notifications.group_utils import sync_group_manager
from notifications.signals import (
    send_role_broadcast_notification,
    send_organization_broadcast,
    send_system_broadcast,
    notify_system_maintenance,
    notify_organization_announcement
)
from organization.models import Organization
from django.utils import timezone
import time

User = get_user_model()


class Command(BaseCommand):
    help = 'Test the enhanced notification group system'

    def add_arguments(self, parser):
        parser.add_argument(
            '--test-type',
            type=str,
            choices=['user', 'role', 'org', 'system', 'all'],
            default='all',
            help='Type of notification test to run'
        )
        parser.add_argument(
            '--org-id',
            type=int,
            help='Organization ID for testing (required for role/org tests)'
        )
        parser.add_argument(
            '--user-id',
            type=int,
            help='User ID for testing (required for user tests)'
        )

    def handle(self, *args, **options):
        test_type = options['test_type']
        org_id = options.get('org_id')
        user_id = options.get('user_id')

        self.stdout.write(
            self.style.SUCCESS(f'Starting notification group tests: {test_type}')
        )

        if test_type in ['user', 'all']:
            self.test_user_notifications(user_id)

        if test_type in ['role', 'all']:
            self.test_role_notifications(org_id)

        if test_type in ['org', 'all']:
            self.test_organization_notifications(org_id)

        if test_type in ['system', 'all']:
            self.test_system_notifications()

        self.stdout.write(
            self.style.SUCCESS('Notification group tests completed!')
        )

    def test_user_notifications(self, user_id=None):
        """Test user-specific notifications"""
        self.stdout.write('Testing user-specific notifications...')

        if not user_id:
            # Get first active user
            user = User.objects.filter(is_active=True).first()
            if not user:
                self.stdout.write(
                    self.style.WARNING('No active users found, skipping user test')
                )
                return
            user_id = user.id
        else:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'User with ID {user_id} not found')
                )
                return

        # Send test notification to specific user
        test_message = {
            'title': 'Test User Notification',
            'message': f'This is a test notification sent directly to user {user.email} at {timezone.now()}',
            'notification_type': 'test_notification',
            'priority': 'medium',
            'category': 'test',
            'is_test': True,
            'created_at': timezone.now().isoformat()
        }

        sync_group_manager.send_to_user(user_id, test_message)
        self.stdout.write(
            self.style.SUCCESS(f'✓ Sent test notification to user {user.email} (ID: {user_id})')
        )

    def test_role_notifications(self, org_id=None):
        """Test role-based notifications"""
        self.stdout.write('Testing role-based notifications...')

        if not org_id:
            # Get first organization
            org = Organization.objects.first()
            if not org:
                self.stdout.write(
                    self.style.WARNING('No organizations found, skipping role test')
                )
                return
            org_id = org.id
        else:
            try:
                org = Organization.objects.get(id=org_id)
            except Organization.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'Organization with ID {org_id} not found')
                )
                return

        # Test role-based broadcast
        send_role_broadcast_notification(
            org_id=org_id,
            role_names=['admin', 'manager'],
            title='Test Role Broadcast',
            message=f'This is a test broadcast to admins and managers in {org.name} at {timezone.now()}',
            notification_type='test_role_broadcast',
            priority='medium'
        )

        self.stdout.write(
            self.style.SUCCESS(f'✓ Sent role broadcast to admins and managers in {org.name}')
        )

        # Test single role notification
        send_role_broadcast_notification(
            org_id=org_id,
            role_names=['team_lead'],
            title='Test Team Lead Notification',
            message=f'This is a test notification for team leads only in {org.name}',
            notification_type='test_team_lead',
            priority='high'
        )

        self.stdout.write(
            self.style.SUCCESS(f'✓ Sent notification to team leads in {org.name}')
        )

    def test_organization_notifications(self, org_id=None):
        """Test organization-wide notifications"""
        self.stdout.write('Testing organization-wide notifications...')

        if not org_id:
            # Get first organization
            org = Organization.objects.first()
            if not org:
                self.stdout.write(
                    self.style.WARNING('No organizations found, skipping org test')
                )
                return
            org_id = org.id
        else:
            try:
                org = Organization.objects.get(id=org_id)
            except Organization.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'Organization with ID {org_id} not found')
                )
                return

        # Test organization announcement
        notify_organization_announcement(
            org_id=org_id,
            title='Test Organization Announcement',
            message=f'This is a test announcement for all members of {org.name}. Please note this is just a test message sent at {timezone.now()}.'
        )

        self.stdout.write(
            self.style.SUCCESS(f'✓ Sent organization announcement to {org.name}')
        )

    def test_system_notifications(self):
        """Test system-wide notifications"""
        self.stdout.write('Testing system-wide notifications...')

        # Test system broadcast
        send_system_broadcast(
            title='Test System Broadcast',
            message=f'This is a test system-wide broadcast sent to all connected users at {timezone.now()}. This is for testing purposes only.',
            notification_type='test_system_broadcast',
            priority='high'
        )

        self.stdout.write(
            self.style.SUCCESS('✓ Sent system-wide broadcast')
        )

        # Test maintenance notification
        notify_system_maintenance(
            start_time='2024-01-01 02:00 UTC',
            duration_minutes=30
        )

        self.stdout.write(
            self.style.SUCCESS('✓ Sent system maintenance notification')
        )

        # Test system admin notification
        test_message = {
            'title': 'Test System Admin Alert',
            'message': f'This is a test alert for system administrators at {timezone.now()}',
            'notification_type': 'test_admin_alert',
            'priority': 'urgent',
            'category': 'security',
            'is_test': True,
            'created_at': timezone.now().isoformat()
        }

        sync_group_manager.send_to_system_admins(test_message)
        self.stdout.write(
            self.style.SUCCESS('✓ Sent notification to system administrators')
        )

    def show_usage_examples(self):
        """Show usage examples"""
        self.stdout.write('\nUsage Examples:')
        self.stdout.write('python manage.py test_notifications --test-type=all')
        self.stdout.write('python manage.py test_notifications --test-type=user --user-id=1')
        self.stdout.write('python manage.py test_notifications --test-type=role --org-id=1')
        self.stdout.write('python manage.py test_notifications --test-type=org --org-id=1')
        self.stdout.write('python manage.py test_notifications --test-type=system')