#!/usr/bin/env python
"""
Script to completely reset the database if all else fails.
This is a nuclear option - use only when other fixes don't work.
"""

import os
import sys
import django
from django.core.management import execute_from_command_line
from django.db import connection

def setup_django():
    """Set up Django environment."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
    django.setup()

def reset_database():
    """Completely reset the database."""
    print("⚠️  NUCLEAR OPTION: Completely resetting database...")
    
    setup_django()
    
    try:
        with connection.cursor() as cursor:
            # Drop all tables except Django's built-in ones
            print("🗑️  Dropping all application tables...")
            
            # Get all tables
            cursor.execute("""
                SELECT tablename FROM pg_tables 
                WHERE schemaname = 'public' 
                AND tablename NOT LIKE 'django_%'
                AND tablename NOT LIKE 'auth_%'
                AND tablename NOT LIKE 'contenttypes_%'
                AND tablename NOT LIKE 'sessions_%'
            """)
            
            tables = [row[0] for row in cursor.fetchall()]
            
            # Disable foreign key checks temporarily
            cursor.execute("SET session_replication_role = replica;")
            
            # Drop all application tables
            for table in tables:
                cursor.execute(f'DROP TABLE IF EXISTS "{table}" CASCADE;')
                print(f"   - Dropped table: {table}")
            
            # Re-enable foreign key checks
            cursor.execute("SET session_replication_role = DEFAULT;")
        
        print("✅ Database reset completed successfully!")
        print("🔄 You should now run migrations and initialization again.")
        return True
        
    except Exception as e:
        print(f"❌ Error resetting database: {e}")
        return False

if __name__ == '__main__':
    # Add backend directory to Python path
    import os
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, backend_dir)
    
    # Ask for confirmation
    response = input("Are you sure you want to completely reset the database? This will delete ALL data! (yes/no): ")
    if response.lower() != 'yes':
        print("Database reset cancelled.")
        sys.exit(0)
    
    success = reset_database()
    sys.exit(0 if success else 1) 