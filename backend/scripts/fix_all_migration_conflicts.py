#!/usr/bin/env python
"""
Comprehensive script to fix all migration conflicts in production.
This script handles cases where migrations try to add columns that already exist.
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

def check_column_exists(table_name, column_name):
    """Check if a column exists in a table."""
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = %s AND column_name = %s
        """, [table_name, column_name])
        return cursor.fetchone() is not None

def check_table_exists(table_name):
    """Check if a table exists."""
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_name = %s
        """, [table_name])
        return cursor.fetchone() is not None

def fix_all_migration_conflicts():
    """Fix all migration conflicts."""
    print("🔧 Fixing all migration conflicts...")
    
    setup_django()
    
    conflicts_fixed = []
    
    # Check and fix Sales_dashboard conflicts
    if check_table_exists('Sales_dashboard_dailystreakrecord'):
        if not check_column_exists('Sales_dashboard_dailystreakrecord', 'streak_value'):
            print("📝 Adding missing streak_value column to Sales_dashboard_dailystreakrecord...")
            with connection.cursor() as cursor:
                cursor.execute("""
                    ALTER TABLE "Sales_dashboard_dailystreakrecord" 
                    ADD COLUMN "streak_value" double precision DEFAULT 0.0
                """)
            conflicts_fixed.append("Added streak_value column to Sales_dashboard_dailystreakrecord")
    
    # Check and fix authentication conflicts
    if check_column_exists('authentication_user', 'role_id'):
        print("📝 Marking authentication migration 0003_add_role_and_user_permissions as applied...")
        try:
            execute_from_command_line([
                'manage.py', 'migrate', 'authentication', '0003_add_role_and_user_permissions', '--fake'
            ])
            conflicts_fixed.append("Marked authentication migration as applied")
        except Exception as e:
            print(f"⚠️  Warning: Could not fake authentication migration: {e}")
    
    # Check and fix Sales_dashboard migrations
    if check_table_exists('Sales_dashboard_dailystreakrecord'):
        print("📝 Marking Sales_dashboard migration as applied...")
        try:
            execute_from_command_line([
                'manage.py', 'migrate', 'Sales_dashboard', '--fake'
            ])
            conflicts_fixed.append("Marked Sales_dashboard migration as applied")
        except Exception as e:
            print(f"⚠️  Warning: Could not fake Sales_dashboard migration: {e}")
    
    # Run any remaining migrations
    print("🔄 Running remaining migrations...")
    try:
        execute_from_command_line(['manage.py', 'migrate'])
        conflicts_fixed.append("Applied remaining migrations")
    except Exception as e:
        print(f"❌ Error running remaining migrations: {e}")
        return False
    
    if conflicts_fixed:
        print("✅ Migration conflicts fixed:")
        for fix in conflicts_fixed:
            print(f"   - {fix}")
    else:
        print("✅ No migration conflicts found")
    
    return True

if __name__ == '__main__':
    # Add backend directory to Python path
    import os
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, backend_dir)
    
    success = fix_all_migration_conflicts()
    sys.exit(0 if success else 1) 