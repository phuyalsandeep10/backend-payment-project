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
            # Clean up orphaned role permissions - be more aggressive
            print("📝 Cleaning orphaned role permissions...")
            try:
                cursor.execute("""
                    DELETE FROM permissions_role_permissions 
                    WHERE permission_id NOT IN (SELECT id FROM auth_permission)
                    OR permission_id IS NULL
                """)
                orphaned_count = cursor.rowcount
                if orphaned_count > 0:
                    print(f"✅ Cleaned up {orphaned_count} orphaned role permissions")
            except Exception as e:
                print(f"⚠️  Warning: Could not clean orphaned role permissions: {e}")
            
            # Specifically clean up permission_id = 30 if it exists
            try:
                cursor.execute("""
                    DELETE FROM permissions_role_permissions 
                    WHERE permission_id = 30
                """)
                specific_count = cursor.rowcount
                if specific_count > 0:
                    print(f"✅ Cleaned up {specific_count} references to permission_id 30")
            except Exception as e:
                print(f"⚠️  Warning: Could not clean permission_id 30: {e}")
            
            # Clean up orphaned user permissions
            print("📝 Cleaning orphaned user permissions...")
            try:
                cursor.execute("""
                    DELETE FROM authentication_user_user_permissions 
                    WHERE permission_id NOT IN (SELECT id FROM auth_permission)
                    OR permission_id IS NULL
                """)
                orphaned_user_perms = cursor.rowcount
                if orphaned_user_perms > 0:
                    print(f"✅ Cleaned up {orphaned_user_perms} orphaned user permissions")
            except Exception as e:
                print(f"⚠️  Warning: Could not clean orphaned user permissions: {e}")
            
            # Clean up orphaned group permissions
            print("📝 Cleaning orphaned group permissions...")
            try:
                cursor.execute("""
                    DELETE FROM auth_group_permissions 
                    WHERE permission_id NOT IN (SELECT id FROM auth_permission)
                    OR permission_id IS NULL
                """)
                orphaned_group_perms = cursor.rowcount
                if orphaned_group_perms > 0:
                    print(f"✅ Cleaned up {orphaned_group_perms} orphaned group permissions")
            except Exception as e:
                print(f"⚠️  Warning: Could not clean orphaned group permissions: {e}")
            
            # Clean up any orphaned roles
            print("📝 Cleaning orphaned roles...")
            try:
                cursor.execute("""
                    DELETE FROM permissions_role 
                    WHERE id NOT IN (
                        SELECT DISTINCT role_id FROM authentication_user WHERE role_id IS NOT NULL
                    ) AND organization_id IS NOT NULL
                """)
                orphaned_roles = cursor.rowcount
                if orphaned_roles > 0:
                    print(f"✅ Cleaned up {orphaned_roles} orphaned roles")
            except Exception as e:
                print(f"⚠️  Warning: Could not clean orphaned roles: {e}")
            
            # Verify the cleanup worked
            try:
                cursor.execute("""
                    SELECT COUNT(*) FROM permissions_role_permissions 
                    WHERE permission_id NOT IN (SELECT id FROM auth_permission)
                """)
                remaining_orphaned = cursor.fetchone()[0]
                if remaining_orphaned == 0:
                    print("✅ All orphaned permissions cleaned successfully!")
                else:
                    print(f"⚠️  Warning: {remaining_orphaned} orphaned permissions still remain")
            except Exception as e:
                print(f"⚠️  Warning: Could not verify cleanup: {e}")
        
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