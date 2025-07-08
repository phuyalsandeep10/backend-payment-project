#!/usr/bin/env python
"""
Script to specifically fix the permission ID 30 issue.
"""

import os
import sys
import django
from django.db import connection

def setup_django():
    """Set up Django environment."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
    django.setup()

def fix_permission_30():
    """Fix the specific permission ID 30 issue."""
    print("🔧 Fixing permission ID 30 issue...")
    
    setup_django()
    
    try:
        with connection.cursor() as cursor:
            # Check if permission ID 30 exists
            cursor.execute("SELECT id, codename FROM auth_permission WHERE id = 30")
            perm_30 = cursor.fetchone()
            
            if perm_30:
                print(f"✅ Permission ID 30 exists: {perm_30[1]}")
            else:
                print("❌ Permission ID 30 does not exist")
                
                # Check what's referencing permission ID 30
                cursor.execute("""
                    SELECT COUNT(*) FROM permissions_role_permissions 
                    WHERE permission_id = 30
                """)
                role_refs = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(*) FROM authentication_user_user_permissions 
                    WHERE permission_id = 30
                """)
                user_refs = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(*) FROM auth_group_permissions 
                    WHERE permission_id = 30
                """)
                group_refs = cursor.fetchone()[0]
                
                print(f"📊 References to permission ID 30:")
                print(f"   - Role permissions: {role_refs}")
                print(f"   - User permissions: {user_refs}")
                print(f"   - Group permissions: {group_refs}")
                
                # Remove all references to permission ID 30
                if role_refs > 0:
                    cursor.execute("DELETE FROM permissions_role_permissions WHERE permission_id = 30")
                    print(f"✅ Removed {role_refs} role permission references")
                
                if user_refs > 0:
                    cursor.execute("DELETE FROM authentication_user_user_permissions WHERE permission_id = 30")
                    print(f"✅ Removed {user_refs} user permission references")
                
                if group_refs > 0:
                    cursor.execute("DELETE FROM auth_group_permissions WHERE permission_id = 30")
                    print(f"✅ Removed {group_refs} group permission references")
        
        print("✅ Permission ID 30 issue fixed!")
        return True
        
    except Exception as e:
        print(f"❌ Error fixing permission ID 30: {e}")
        return False

if __name__ == '__main__':
    # Add backend directory to Python path
    import os
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, backend_dir)
    
    success = fix_permission_30()
    sys.exit(0 if success else 1) 