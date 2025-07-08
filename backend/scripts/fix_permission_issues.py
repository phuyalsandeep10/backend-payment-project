#!/usr/bin/env python
"""
Script to check and fix permission-related issues.
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

def check_permission_issues():
    """Check for permission-related issues."""
    print("🔍 Checking for permission issues...")
    
    setup_django()
    
    from django.contrib.auth.models import Permission
    from permissions.models import Role
    
    issues_found = []
    
    # Check for orphaned role permissions
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT COUNT(*) FROM permissions_role_permissions 
            WHERE permission_id NOT IN (SELECT id FROM auth_permission)
        """)
        orphaned_count = cursor.fetchone()[0]
        
        if orphaned_count > 0:
            issues_found.append(f"Found {orphaned_count} orphaned role permissions")
            print(f"❌ Found {orphaned_count} orphaned role permissions")
            
            # Clean up orphaned permissions
            cursor.execute("""
                DELETE FROM permissions_role_permissions 
                WHERE permission_id NOT IN (SELECT id FROM auth_permission)
            """)
            print(f"✅ Cleaned up {orphaned_count} orphaned role permissions")
    
    # Check for roles with no permissions
    roles_without_permissions = Role.objects.filter(permissions__isnull=True).count()
    if roles_without_permissions > 0:
        issues_found.append(f"Found {roles_without_permissions} roles without permissions")
        print(f"⚠️  Found {roles_without_permissions} roles without permissions")
    
    if not issues_found:
        print("✅ No permission issues found")
    
    return len(issues_found) == 0

if __name__ == '__main__':
    # Add backend directory to Python path
    import os
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, backend_dir)
    
    success = check_permission_issues()
    sys.exit(0 if success else 1) 