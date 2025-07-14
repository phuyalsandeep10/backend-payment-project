#!/usr/bin/env python
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from authentication.models import User
from permissions.models import Role, Permission

def check_user_permissions(email):
    """Check user's role and permissions"""
    try:
        user = User.objects.get(email=email)
        print(f"User: {user.email}")
        print(f"Role: {user.role.name if user.role else 'No role'}")
        print(f"Organization: {user.organization.name if user.organization else 'No organization'}")
        
        if user.role:
            print(f"\nPermissions for role '{user.role.name}':")
            permissions = user.role.permissions.all()
            for perm in permissions:
                print(f"  - {perm.codename}: {perm.name}")
            
            # Check specific commission permissions
            commission_perms = ['edit_commission', 'view_all_commissions', 'view_commission', 'add_commission', 'delete_commission']
            print(f"\nCommission permissions check:")
            for perm_name in commission_perms:
                has_perm = user.role.permissions.filter(codename=perm_name).exists()
                print(f"  - {perm_name}: {'✓' if has_perm else '✗'}")
        else:
            print("User has no role assigned!")
            
    except User.DoesNotExist:
        print(f"User with email {email} not found!")

if __name__ == "__main__":
    # Replace with the actual user email you're testing with
    email = input("Enter user email to check permissions: ")
    check_user_permissions(email) 