#!/usr/bin/env python
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from permissions.models import Role, Permission
from authentication.models import User

def check_and_fix_salesperson_permissions():
    print("=== Checking Salesperson Permissions ===")
    
    # Get the Salesperson role
    try:
        salesperson_role = Role.objects.get(name='Salesperson')
        print(f"Found Salesperson role: {salesperson_role}")
    except Role.DoesNotExist:
        print("❌ Salesperson role not found!")
        return
    
    # Get current permissions
    current_permissions = list(salesperson_role.permissions.values_list('codename', flat=True))
    print(f"Current permissions ({len(current_permissions)}): {current_permissions}")
    
    # Required permissions for deals
    required_deal_permissions = [
        'view_all_deals',
        'view_own_deals', 
        'create_deal',
        'edit_deal',
        'delete_deal',
        'log_deal_activity'
    ]
    
    # Check which permissions are missing
    missing_permissions = []
    for perm_codename in required_deal_permissions:
        if perm_codename not in current_permissions:
            missing_permissions.append(perm_codename)
    
    if missing_permissions:
        print(f"❌ Missing permissions: {missing_permissions}")
        
        # Create missing permissions
        for perm_codename in missing_permissions:
            perm, created = Permission.objects.get_or_create(
                codename=perm_codename,
                defaults={
                    'name': f'Can {perm_codename.replace("_", " ")}',
                    'category': 'deals'
                }
            )
            if created:
                print(f"✅ Created permission: {perm_codename}")
        
        # Add permissions to role
        for perm_codename in missing_permissions:
            try:
                perm = Permission.objects.get(codename=perm_codename)
                salesperson_role.permissions.add(perm)
                print(f"✅ Added permission '{perm_codename}' to Salesperson role")
            except Permission.DoesNotExist:
                print(f"❌ Failed to find permission: {perm_codename}")
    else:
        print("✅ All required permissions are present!")
    
    # Verify the user has the role
    try:
        sales_user = User.objects.get(email='sales@innovate.com')
        print(f"✅ Found sales user: {sales_user.email}")
        print(f"   Role: {sales_user.role}")
        print(f"   Organization: {sales_user.organization}")
    except User.DoesNotExist:
        print("❌ Sales user not found!")

if __name__ == "__main__":
    check_and_fix_salesperson_permissions() 