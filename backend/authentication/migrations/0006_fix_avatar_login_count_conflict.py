# Generated manually to fix deployment migration conflicts

from django.db import migrations, models


def safe_remove_avatar_and_add_login_count(apps, schema_editor):
    """
    Safely remove avatar column if it exists and add login_count if it doesn't exist.
    This handles the deployment environment where avatar column may not exist.
    """
    db_alias = schema_editor.connection.alias
    with schema_editor.connection.cursor() as cursor:
        # Check if the avatar column exists and remove it if it does
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'authentication_user' 
            AND column_name = 'avatar'
        """)
        if cursor.fetchone():
            # Column exists, remove it
            schema_editor.execute("ALTER TABLE authentication_user DROP COLUMN avatar")
        
        # Check if the login_count column exists and add it if it doesn't
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'authentication_user' 
            AND column_name = 'login_count'
        """)
        if not cursor.fetchone():
            # Column doesn't exist, add it
            schema_editor.execute("ALTER TABLE authentication_user ADD COLUMN login_count integer DEFAULT 0")


def reverse_safe_operations(apps, schema_editor):
    """
    Reverse operation - this is a no-op since we don't want to add avatar back
    and login_count should remain.
    """
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("authentication", "0005_user_login_count"),
    ]

    operations = [
        migrations.RunPython(
            safe_remove_avatar_and_add_login_count,
            reverse_safe_operations,
        ),
    ] 