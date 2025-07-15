#!/usr/bin/env python
"""
Safe migration checker and runner for deployment.
This script ensures migrations are run before any other database operations.
"""
import os
import sys
import django
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

def check_migrations_status():
    """Check if migrations are needed."""
    print("🔍 Checking Migration Status")
    print("=" * 50)
    
    try:
        django.setup()
        from django.core.management import execute_from_command_line
        from django.db import connection
        
        # Check if we can connect to the database
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1;")
            print("✅ Database connection successful")
        
        # Check for unapplied migrations
        from django.core.management import call_command
        from io import StringIO
        
        # Capture the output of showmigrations
        out = StringIO()
        call_command('showmigrations', stdout=out)
        migrations_output = out.getvalue()
        
        # Check if there are any unapplied migrations
        unapplied = []
        for line in migrations_output.split('\n'):
            if '[ ]' in line:  # Unapplied migration
                unapplied.append(line.strip())
        
        if unapplied:
            print(f"⚠️  Found {len(unapplied)} unapplied migrations:")
            for migration in unapplied[:5]:  # Show first 5
                print(f"   {migration}")
            if len(unapplied) > 5:
                print(f"   ... and {len(unapplied) - 5} more")
            return True
        else:
            print("✅ All migrations are applied")
            return False
            
    except Exception as e:
        print(f"❌ Error checking migrations: {e}")
        return True  # Assume migrations are needed if we can't check

def run_migrations():
    """Run migrations safely."""
    print("\n🔄 Running Migrations")
    print("=" * 50)
    
    try:
        from django.core.management import call_command
        
        # Run migrations
        call_command('migrate', verbosity=1)
        print("✅ Migrations completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error running migrations: {e}")
        return False

def check_tables_exist():
    """Check if key tables exist."""
    print("\n🔍 Checking Database Tables")
    print("=" * 50)
    
    try:
        from django.db import connection
        
        # List of key tables that should exist
        key_tables = [
            'django_migrations',
            'django_content_type',
            'django_admin_log',
            'auth_user',
            'authentication_user',
            'notifications_notification',
        ]
        
        missing_tables = []
        
        with connection.cursor() as cursor:
            for table in key_tables:
                try:
                    cursor.execute(f"SELECT 1 FROM {table} LIMIT 1;")
                    print(f"✅ {table}")
                except Exception:
                    print(f"❌ {table} - does not exist")
                    missing_tables.append(table)
        
        if missing_tables:
            print(f"\n⚠️  Missing tables: {', '.join(missing_tables)}")
            return False
        else:
            print("\n✅ All key tables exist")
            return True
            
    except Exception as e:
        print(f"❌ Error checking tables: {e}")
        return False

def main():
    """Main function."""
    print("🚀 Migration Checker and Runner")
    print("=" * 60)
    
    # Step 1: Check if migrations are needed
    migrations_needed = check_migrations_status()
    
    if migrations_needed:
        # Step 2: Run migrations
        migrations_success = run_migrations()
        
        if not migrations_success:
            print("\n❌ Migration failed - cannot proceed")
            sys.exit(1)
    
    # Step 3: Check if tables exist
    tables_ok = check_tables_exist()
    
    # Summary
    print(f"\n📊 Summary")
    print("=" * 50)
    print(f"Migrations Needed: {'Yes' if migrations_needed else 'No'}")
    print(f"Migrations Success: {'✅ Yes' if not migrations_needed or migrations_success else '❌ No'}")
    print(f"Tables Ready: {'✅ Yes' if tables_ok else '❌ No'}")
    
    if tables_ok:
        print("\n🎉 Database is ready for application operations!")
        return True
    else:
        print("\n⚠️  Database tables are not ready")
        return False

if __name__ == '__main__':
    success = main()
    if not success:
        sys.exit(1) 