from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('notifications', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notification',
            name='notification_type',
            field=models.CharField(
                choices=[
                    ('client_created', 'New Client Created'),
                    ('deal_created', 'New Deal Created'),
                    ('deal_updated', 'Deal Updated'), 
                    ('deal_status_changed', 'Deal Status Changed'),
                    ('user_created', 'New User Created'),
                    ('role_created', 'New Role Created'),
                    ('team_created', 'New Team Created'),
                    ('project_created', 'New Project Created'),
                    ('commission_created', 'New Commission Created'),
                    ('payment_received', 'Payment Received'),
                    ('new_organization', 'New Organization Created'),
                    ('system_alert', 'System Alert'),
                    ('system_maintenance', 'System Maintenance'),
                    ('organization_announcement', 'Organization Announcement'),
                    ('test_system_broadcast', 'Test System Broadcast'),
                    ('test_notification', 'Test Notification'),
                ],
                max_length=50
            ),
        ),
    ]
