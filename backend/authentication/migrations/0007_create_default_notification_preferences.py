from django.db import migrations

def create_default_notification_preferences(apps, schema_editor):
    """Create default notification preferences for existing users"""
    User = apps.get_model('authentication', 'User')
    UserNotificationPreferences = apps.get_model('authentication', 'UserNotificationPreferences')
    
    for user in User.objects.all():
        if not hasattr(user, 'notification_preferences') or not user.notification_preferences:
            UserNotificationPreferences.objects.get_or_create(
                user=user,
                defaults={
                    'desktop_notifications': True,
                    'unread_badge': False,
                    'push_timeout': 'select',
                    'communication_emails': True,
                    'announcements_updates': False,
                    'notification_sounds': True,
                }
            )

def reverse_create_default_notification_preferences(apps, schema_editor):
    """Remove all notification preferences"""
    UserNotificationPreferences = apps.get_model('authentication', 'UserNotificationPreferences')
    UserNotificationPreferences.objects.all().delete()

class Migration(migrations.Migration):
    dependencies = [
        ('authentication', '0006_user_address_usernotificationpreferences'),
    ]

    operations = [
        migrations.RunPython(
            create_default_notification_preferences,
            reverse_create_default_notification_preferences
        ),
    ] 