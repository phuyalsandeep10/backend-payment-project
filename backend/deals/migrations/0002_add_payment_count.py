# Generated manually to fix payment_count column issue

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('deals', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='deal',
            name='payment_count',
            field=models.IntegerField(
                default=0,
                help_text='Number of payments made for this deal'
            ),
        ),
    ] 