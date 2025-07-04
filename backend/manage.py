#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def run_initial_setup():
    """Run migrations and app initialization automatically."""
    from django.core.management import execute_from_command_line
    from django.db import connection
    from django.core.management.base import CommandError
    
    print("🚀 Auto-running initial setup...")
    
    try:
        # Check if database connection works and if tables exist
        with connection.cursor() as cursor:
            # Try to check if django_migrations table exists (created by migrate)
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='django_migrations'
                UNION ALL
                SELECT tablename FROM pg_tables 
                WHERE tablename='django_migrations'
            """)
            result = cursor.fetchone()
            
            if not result:
                print("📊 Database tables not found. Running migrations...")
                execute_from_command_line(['manage.py', 'migrate'])
                print("✅ Migrations completed!")
            else:
                print("📊 Database tables exist. Running migrations to ensure they're up to date...")
                execute_from_command_line(['manage.py', 'migrate'])
                print("✅ Migrations up to date!")
                
    except Exception as e:
        print(f"📊 Database not ready or error occurred: {e}")
        print("📊 Running migrations...")
        try:
            execute_from_command_line(['manage.py', 'migrate'])
            print("✅ Migrations completed!")
        except Exception as migrate_error:
            print(f"❌ Migration failed: {migrate_error}")
            return
    
    # Run app initialization
    try:
        print("🔧 Running app initialization...")
        execute_from_command_line(['manage.py', 'initialize_app'])
        print("✅ App initialization completed!")
    except CommandError as e:
        if "already initialized" in str(e).lower():
            print("ℹ️ App already initialized. Skipping...")
        else:
            print(f"⚠️ App initialization warning: {e}")
    except Exception as e:
        print(f"❌ App initialization failed: {e}")


def main():
    """Run administrative tasks."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core_config.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    
    # Check if this is a runserver command
    if len(sys.argv) > 1 and sys.argv[1] == 'runserver':
        print("🌟 Starting Django server with auto-setup...")
        run_initial_setup()
        print("🚀 Starting Django development server...")
    
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()