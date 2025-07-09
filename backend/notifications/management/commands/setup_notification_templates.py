from django.core.management.base import BaseCommand
from notifications.models import NotificationTemplate
from django.contrib.auth import get_user_model

User = get_user_model()

class Command(BaseCommand):
    help = "Set up basic notification templates for all notification types"

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Setting up notification templates..."))
        
        # Get or create a system user for template creation
        system_user, created = User.objects.get_or_create(
            username='system',
            defaults={
                'email': 'system@example.com',
                'first_name': 'System',
                'last_name': 'User',
                'is_active': False,
                'is_staff': True,
                'is_superuser': True
            }
        )
        
        templates_data = [
            {
                'notification_type': 'client_created',
                'title_template': 'New Client: {client_name}',
                'message_template': 'A new client "{client_name}" has been added to the system by {created_by}.',
                'available_variables': '{"client_name": "Name of the client", "created_by": "User who created the client"}'
            },
            {
                'notification_type': 'deal_created',
                'title_template': 'New Deal: {deal_name}',
                'message_template': 'A new deal "{deal_name}" worth ${deal_value} has been created by {created_by}.',
                'available_variables': '{"deal_name": "Name of the deal", "deal_value": "Value of the deal", "created_by": "User who created the deal"}'
            },
            {
                'notification_type': 'deal_updated',
                'title_template': 'Deal Updated: {deal_name}',
                'message_template': 'The deal "{deal_name}" has been updated by {updated_by}.',
                'available_variables': '{"deal_name": "Name of the deal", "updated_by": "User who updated the deal"}'
            },
            {
                'notification_type': 'deal_status_changed',
                'title_template': 'Deal Status Changed: {deal_name}',
                'message_template': 'The status of deal "{deal_name}" has been changed to {new_status}.',
                'available_variables': '{"deal_name": "Name of the deal", "new_status": "New status of the deal"}'
            },
            {
                'notification_type': 'user_created',
                'title_template': 'New User: {user_name}',
                'message_template': 'A new user "{user_name}" with role "{role_name}" has been added to the organization.',
                'available_variables': '{"user_name": "Name of the new user", "role_name": "Role assigned to the user"}'
            },
            {
                'notification_type': 'role_created',
                'title_template': 'New Role: {role_name}',
                'message_template': 'A new role "{role_name}" has been created with {permission_count} permissions.',
                'available_variables': '{"role_name": "Name of the new role", "permission_count": "Number of permissions assigned"}'
            },
            {
                'notification_type': 'team_created',
                'title_template': 'New Team: {team_name}',
                'message_template': 'A new team "{team_name}" has been created with team lead: {team_lead}.',
                'available_variables': '{"team_name": "Name of the new team", "team_lead": "Name of the team lead"}'
            },
            {
                'notification_type': 'project_created',
                'title_template': 'New Project: {project_name}',
                'message_template': 'A new project "{project_name}" has been created by {created_by}.',
                'available_variables': '{"project_name": "Name of the new project", "created_by": "User who created the project"}'
            },
            {
                'notification_type': 'commission_created',
                'title_template': 'New Commission: {user_name}',
                'message_template': 'A commission of ${commission_amount} has been calculated for {user_name}.',
                'available_variables': '{"user_name": "Name of the user", "commission_amount": "Commission amount"}'
            },
            {
                'notification_type': 'payment_received',
                'title_template': 'Payment Received: ${amount}',
                'message_template': 'Payment of ${amount} has been received for deal "{deal_id}" on {payment_date}.',
                'available_variables': '{"amount": "Payment amount", "deal_id": "ID of the deal", "payment_date": "Date of payment"}'
            },
            {
                'notification_type': 'new_organization',
                'title_template': 'New Organization: {org_name}',
                'message_template': 'A new organization "{org_name}" has been registered in the PRS system.',
                'available_variables': '{"org_name": "Name of the new organization"}'
            },
            {
                'notification_type': 'system_alert',
                'title_template': 'System Alert: {alert_type}',
                'message_template': 'System alert: {alert_message}',
                'available_variables': '{"alert_type": "Type of alert", "alert_message": "Alert message"}'
            }
        ]
        
        created_count = 0
        for template_data in templates_data:
            template, created = NotificationTemplate.objects.get_or_create(
                notification_type=template_data['notification_type'],
                defaults={
                    'title_template': template_data['title_template'],
                    'message_template': template_data['message_template'],
                    'available_variables': template_data['available_variables'],
                    'is_active': True,
                    'created_by': system_user,
                    'updated_by': system_user
                }
            )
            if created:
                created_count += 1
                self.stdout.write(f"✅ Created template: {template_data['notification_type']}")
            else:
                self.stdout.write(f"ℹ️  Template already exists: {template_data['notification_type']}")
        
        self.stdout.write(self.style.SUCCESS(f"✅ Setup complete! {created_count} new templates created.")) 