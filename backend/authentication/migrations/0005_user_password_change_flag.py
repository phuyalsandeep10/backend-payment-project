from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0004_user_avatar_user_status_activity_notification'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='must_change_password',
            field=models.BooleanField(default=False, help_text='Require user to change password at next login'),
        ),
    ] 