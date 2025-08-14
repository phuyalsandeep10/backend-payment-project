# Generated manually for SecureUserSession model

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0005_alter_user_options_alter_userprofile_profile_picture_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='SecureUserSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_id', models.CharField(db_index=True, max_length=128, unique=True)),
                ('jwt_token_id', models.CharField(db_index=True, help_text='JWT token ID (jti claim)', max_length=128)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_activity', models.DateTimeField(auto_now=True)),
                ('expires_at', models.DateTimeField(db_index=True)),
                ('is_active', models.BooleanField(db_index=True, default=True)),
                ('ip_address', models.GenericIPAddressField(db_index=True)),
                ('user_agent', models.TextField()),
                ('user_agent_hash', models.CharField(db_index=True, max_length=64)),
                ('session_fingerprint', models.CharField(db_index=True, max_length=64)),
                ('login_method', models.CharField(db_index=True, default='jwt', max_length=20)),
                ('device_type', models.CharField(blank=True, max_length=50, null=True)),
                ('browser_name', models.CharField(blank=True, max_length=50, null=True)),
                ('os_name', models.CharField(blank=True, max_length=50, null=True)),
                ('is_suspicious', models.BooleanField(db_index=True, default=False)),
                ('suspicious_reason', models.CharField(blank=True, max_length=200, null=True)),
                ('flagged_at', models.DateTimeField(blank=True, null=True)),
                ('ip_verified', models.BooleanField(default=True)),
                ('user_agent_verified', models.BooleanField(default=True)),
                ('fingerprint_verified', models.BooleanField(default=True)),
                ('login_location', models.CharField(blank=True, max_length=100, null=True)),
                ('timezone', models.CharField(blank=True, max_length=50, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='secure_sessions', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Secure User Session',
                'verbose_name_plural': 'Secure User Sessions',
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['user', 'is_active'], name='authenticat_user_id_b8e8c5_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['user', 'created_at'], name='authenticat_user_id_0c7b8a_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['session_id'], name='authenticat_session_4b5c6d_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['jwt_token_id'], name='authenticat_jwt_tok_7e8f9a_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['ip_address', 'created_at'], name='authenticat_ip_addr_1a2b3c_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['user_agent_hash'], name='authenticat_user_ag_4d5e6f_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['session_fingerprint'], name='authenticat_session_7g8h9i_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['is_suspicious', 'created_at'], name='authenticat_is_susp_0j1k2l_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['expires_at'], name='authenticat_expires_3m4n5o_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['last_activity'], name='authenticat_last_ac_6p7q8r_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['is_active', 'expires_at'], name='authenticat_is_acti_9s0t1u_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['login_method', 'created_at'], name='authenticat_login_m_2v3w4x_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['device_type', 'created_at'], name='authenticat_device__5y6z7a_idx'),
        ),
        migrations.AddIndex(
            model_name='secureuserSession',
            index=models.Index(fields=['browser_name', 'created_at'], name='authenticat_browser_8b9c0d_idx'),
        ),
    ]