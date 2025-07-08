#!/usr/bin/env python
"""
Script to completely clean the database of orphaned data before initialization.
This should be run before any initialization to ensure a clean state.
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

def clean_database():
    """Clean the database of orphaned data."""
    print("🧹 Cleaning database of orphaned data...")
    
    setup_django()
    
    try:
        with connection.cursor() as cursor:
            # Clean up orphaned role permissions
            print("📝 Cleaning orphaned role permissions...")
            cursor.execute("""
                DELETE FROM permissions_role_permissions 
                WHERE permission_id NOT IN (SELECT id FROM auth_permission)
            """)
            orphaned_count = cursor.rowcount
            if orphaned_count > 0:
                print(f"✅ Cleaned up {orphaned_count} orphaned role permissions")
            
            # Clean up orphaned user permissions
            print("📝 Cleaning orphaned user permissions...")
            cursor.execute("""
                DELETE FROM authentication_user_user_permissions 
                WHERE permission_id NOT IN (SELECT id FROM auth_permission)
            """)
            orphaned_user_perms = cursor.rowcount
            if orphaned_user_perms > 0:
                print(f"✅ Cleaned up {orphaned_user_perms} orphaned user permissions")
            
            # Clean up orphaned group permissions
            print("📝 Cleaning orphaned group permissions...")
            cursor.execute("""
                DELETE FROM auth_group_permissions 
                WHERE permission_id NOT IN (SELECT id FROM auth_permission)
            """)
            orphaned_group_perms = cursor.rowcount
            if orphaned_group_perms > 0:
                print(f"✅ Cleaned up {orphaned_group_perms} orphaned group permissions")
            
            # Clean up any orphaned roles
            print("📝 Cleaning orphaned roles...")
            cursor.execute("""
                DELETE FROM permissions_role 
                WHERE id NOT IN (
                    SELECT DISTINCT role_id FROM authentication_user WHERE role_id IS NOT NULL
                ) AND organization_id IS NOT NULL
            """)
            orphaned_roles = cursor.rowcount
            if orphaned_roles > 0:
                print(f"✅ Cleaned up {orphaned_roles} orphaned roles")
        
        print("✅ Database cleaning completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error cleaning database: {e}")
        return False

if __name__ == '__main__':
    # Add backend directory to Python path
    import os
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, backend_dir)
    
    success = clean_database()
    sys.exit(0 if success else 1) 