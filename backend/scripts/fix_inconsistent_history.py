#!/usr/bin/env python
import os
import sys
import django
from django.db import connection, IntegrityError
from django.core.management import execute_from_command_line
from django.utils import timezone

def setup_django():
    """Set up Django environment."""
    # Add backend directory to Python path
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, backend_dir)
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
    django.setup()

def fix_inconsistent_history():
    """
    Fix InconsistentMigrationHistory errors by manually inserting
    missing migration records.
    """
    print("🔧 Fixing InconsistentMigrationHistory...")
    setup_django()

    migrations_to_add = [
        ('authentication', '0001_initial'),
        ('organization', '0001_initial'),
        ('project', '0001_initial'),
    ]

    try:
        with connection.cursor() as cursor:
            for app, name in migrations_to_add:
                print(f"📝 Inserting missing migration record for {app}.{name}...")
                try:
                    cursor.execute(
                        "INSERT INTO django_migrations (app, name, applied) VALUES (%s, %s, %s)",
                        [app, name, timezone.now()]
                    )
                    print(f"✅ Record for {app}.{name} inserted successfully.")
                except IntegrityError:
                    print(f"✅ Record for {app}.{name} already exists. Skipping insertion.")

    except Exception as e:
        print(f"❌ Error during manual migration fix: {e}")
        return False

    print("🔄 Now, trying to run migrations again...")
    try:
        execute_from_command_line(['manage.py', 'migrate'])
        print("✅ Migrations ran successfully!")
    except Exception as e:
        print(f"❌ Error running migrations after fix: {e}")
        return False

    return True

if __name__ == '__main__':
    success = fix_inconsistent_history()
    sys.exit(0 if success else 1) 