#!/usr/bin/env python
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from authentication.models import User
from permissions.models import Role, Permission
from organization.models import Organization

def verify_deployment_permissions():
    """Comprehensive verification of deployment permissions."""
    print("🔍 === DEPLOYMENT PERMISSION VERIFICATION ===")
    
    # Check organizations
    print("\n📋 Checking Organizations:")
    organizations = Organization.objects.all()
    if organizations.exists():
        for org in organizations:
            print(f"✅ Organization: {org.name}")
    else:
        print("❌ No organizations found!")
        return False
    
    # Check roles
    print("\n👥 Checking Roles:")
    roles = Role.objects.all()
    expected_roles = ["Super Admin", "Organization Admin", "Salesperson", "Verifier"]
    
    for role_name in expected_roles:
        org_roles = roles.filter(name=role_name)
        if org_roles.exists():
            for role in org_roles:
                org_name = role.organization.name if role.organization else "System"
                perm_count = role.permissions.count()
                print(f"✅ Role: {role_name} ({org_name}) - {perm_count} permissions")
        else:
            print(f"❌ Role '{role_name}' not found!")
    
    # Check users
    print("\n👤 Checking Users:")
    test_users = {
        "sales@innovate.com": "Salesperson",
        "verifier@innovate.com": "Verifier", 
        "orgadmin@innovate.com": "Organization Admin",
        "super@innovate.com": "Super Admin"
    }
    
    for email, expected_role in test_users.items():
        try:
            user = User.objects.get(email=email)
            role_name = user.role.name if user.role else "No Role"
            org_name = user.organization.name if user.organization else "No Org"
            is_active = user.is_active
            is_superuser = user.is_superuser
            
            status = "✅" if role_name == expected_role and is_active else "❌"
            print(f"{status} User: {email}")
            print(f"   Role: {role_name} (expected: {expected_role})")
            print(f"   Organization: {org_name}")
            print(f"   Active: {is_active}, Superuser: {is_superuser}")
            
            if user.role:
                permissions = list(user.role.permissions.values_list('codename', flat=True))
                print(f"   Permissions: {len(permissions)}")
                
                # Check for critical permissions based on role
                if expected_role == "Salesperson":
                    critical_perms = ['view_all_deals', 'create_deal', 'view_all_clients']
                    missing = [perm for perm in critical_perms if perm not in permissions]
                    if missing:
                        print(f"   ❌ Missing critical permissions: {missing}")
                    else:
                        print(f"   ✅ All critical permissions present")
                        
        except User.DoesNotExist:
            print(f"❌ User {email} not found!")
    
    # Check permissions
    print("\n🔐 Checking Permissions:")
    total_permissions = Permission.objects.count()
    print(f"Total permissions in system: {total_permissions}")
    
    # Check critical permissions exist
    critical_permissions = [
        'view_all_deals', 'create_deal', 'edit_deal', 'delete_deal',
        'view_all_clients', 'create_new_client', 'edit_client_details',
        'view_payment_verification_dashboard', 'verify_deal_payment'
    ]
    
    for perm_codename in critical_permissions:
        try:
            perm = Permission.objects.get(codename=perm_codename)
            print(f"✅ Permission: {perm_codename}")
        except Permission.DoesNotExist:
            print(f"❌ Missing permission: {perm_codename}")
    
    # Test dashboard access simulation
    print("\n🎯 Testing Dashboard Access Simulation:")
    try:
        sales_user = User.objects.get(email='sales@innovate.com')
        if sales_user.role and sales_user.role.name == 'Salesperson':
            permissions = list(sales_user.role.permissions.values_list('codename', flat=True))
            
            # Simulate the IsSalesperson permission check
            has_salesperson_role = sales_user.role.name == 'Salesperson'
            has_required_perms = all(perm in permissions for perm in ['view_all_deals', 'create_deal'])
            
            if has_salesperson_role and has_required_perms:
                print("✅ Dashboard access should work - all conditions met")
                print(f"   Role check: {has_salesperson_role}")
                print(f"   Permission check: {has_required_perms}")
            else:
                print("❌ Dashboard access will fail!")
                print(f"   Role check: {has_salesperson_role}")
                print(f"   Permission check: {has_required_perms}")
        else:
            print("❌ User doesn't have Salesperson role!")
            
    except User.DoesNotExist:
        print("❌ Sales user not found!")
    
    print("\n🎉 Verification complete!")
    return True

if __name__ == "__main__":
    verify_deployment_permissions() 