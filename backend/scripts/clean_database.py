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

def table_exists(cursor, table_name):
    """Check if a table exists in the database."""
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = %s
        );
    """, [table_name])
    return cursor.fetchone()[0]

def clean_database():
    """Clean the database of orphaned data."""
    print("🧹 Cleaning database of orphaned data...")
    
    setup_django()
    
    try:
        with connection.cursor() as cursor:
            # Clean up orphaned role permissions - be more aggressive
            if table_exists(cursor, 'permissions_role_permissions'):
                print("📝 Cleaning orphaned role permissions...")
                cursor.execute("""
                    DELETE FROM permissions_role_permissions 
                    WHERE permission_id NOT IN (SELECT id FROM auth_permission)
                    OR permission_id IS NULL
                """)
                orphaned_count = cursor.rowcount
                print(f"✅ Cleaned up {orphaned_count} orphaned role permissions.")
            else:
                print("ℹ️  Table 'permissions_role_permissions' not found, skipping cleanup.")

            # Clean up orphaned user permissions
            if table_exists(cursor, 'authentication_user_user_permissions'):
                print("📝 Cleaning orphaned user permissions...")
                cursor.execute("""
                    DELETE FROM authentication_user_user_permissions 
                    WHERE permission_id NOT IN (SELECT id FROM auth_permission)
                    OR permission_id IS NULL
                """)
                orphaned_user_perms = cursor.rowcount
                print(f"✅ Cleaned up {orphaned_user_perms} orphaned user permissions.")
            else:
                print("ℹ️  Table 'authentication_user_user_permissions' not found, skipping cleanup.")

            # Clean up orphaned group permissions
            if table_exists(cursor, 'auth_group_permissions'):
                print("📝 Cleaning orphaned group permissions...")
                cursor.execute("""
                    DELETE FROM auth_group_permissions 
                    WHERE permission_id NOT IN (SELECT id FROM auth_permission)
                    OR permission_id IS NULL
                """)
                orphaned_group_perms = cursor.rowcount
                print(f"✅ Cleaned up {orphaned_group_perms} orphaned group permissions.")
            else:
                print("ℹ️  Table 'auth_group_permissions' not found, skipping cleanup.")

            # Clean up any orphaned roles
            if table_exists(cursor, 'permissions_role'):
                print("📝 Cleaning orphaned roles (roles not assigned to any user)...")
                cursor.execute("""
                    DELETE FROM permissions_role 
                    WHERE id NOT IN (
                        SELECT DISTINCT role_id FROM authentication_user WHERE role_id IS NOT NULL
                    ) AND organization_id IS NOT NULL -- Only delete org-specific roles, not templates
                """)
                orphaned_roles = cursor.rowcount
                print(f"✅ Cleaned up {orphaned_roles} orphaned roles.")
            else:
                print("ℹ️  Table 'permissions_role' not found, skipping cleanup.")

            # Verify the cleanup worked
            if table_exists(cursor, 'permissions_role_permissions'):
                print("🔍 Verifying cleanup...")
                cursor.execute("""
                    SELECT COUNT(*) FROM permissions_role_permissions 
                    WHERE permission_id NOT IN (SELECT id FROM auth_permission)
                """)
                remaining_orphaned = cursor.fetchone()[0]
                if remaining_orphaned == 0:
                    print("✅ All orphaned permissions cleaned successfully!")
                else:
                    print(f"⚠️  Warning: {remaining_orphaned} orphaned permissions still remain")

        print("✅ Database cleaning script finished.")
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