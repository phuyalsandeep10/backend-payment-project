#!/usr/bin/env python
"""
Script to set must_change_password=True for org admin users
This allows testing the OTP + password change flow for org admins
"""

import os
import sys
import django

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from authentication.models import User
from permissions.models import Role

def fix_org_admin_password_change():
    """Set must_change_password=True for all org admin users"""
    
    # Find all org admin roles
    org_admin_roles = Role.objects.filter(
        name__icontains='admin',
        organization__isnull=False  # Only org-specific admin roles
    )
    
    print(f"Found {org_admin_roles.count()} org admin roles:")
    for role in org_admin_roles:
        print(f"  - {role.name} (Org: {role.organization.name if role.organization else 'None'})")
    
    # Find all users with org admin roles
    org_admin_users = User.objects.filter(
        role__in=org_admin_roles,
        is_active=True
    )
    
    print(f"\nFound {org_admin_users.count()} org admin users:")
    
    updated_count = 0
    for user in org_admin_users:
        print(f"  - {user.email} (Role: {user.role.name}, Org: {user.organization.name if user.organization else 'None'})")
        
        if not user.must_change_password:
            user.must_change_password = True
            user.save(update_fields=['must_change_password'])
            print(f"    ✅ Set must_change_password=True")
            updated_count += 1
        else:
            print(f"    ℹ️  Already has must_change_password=True")
    
    print(f"\n✅ Updated {updated_count} org admin users to require password change")
    
    # Also check for any users with 'admin' in their role name
    admin_users = User.objects.filter(
        role__name__icontains='admin',
        is_active=True
    ).exclude(role__in=org_admin_roles)
    
    if admin_users.exists():
        print(f"\nFound {admin_users.count()} additional admin users:")
        for user in admin_users:
            print(f"  - {user.email} (Role: {user.role.name}, Org: {user.organization.name if user.organization else 'None'})")
            
            if not user.must_change_password:
                user.must_change_password = True
                user.save(update_fields=['must_change_password'])
                print(f"    ✅ Set must_change_password=True")
                updated_count += 1
            else:
                print(f"    ℹ️  Already has must_change_password=True")

if __name__ == '__main__':
    fix_org_admin_password_change() 