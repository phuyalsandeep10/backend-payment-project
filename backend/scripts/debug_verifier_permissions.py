#!/usr/bin/env python
"""
Debug Verifier Permissions Script
Checks the current state of verifier user permissions and role assignment.
"""

import os
import sys
import django

# Add the backend directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from authentication.models import User
from permissions.models import Role
from organization.models import Organization


def check_verifier_user():
    """Check the verifier user's current state."""
    print("🔍 Checking Verifier User...")
    
    try:
        verifier_user = User.objects.get(username='verifier')
        print(f"✅ Found verifier user: {verifier_user.email}")
        print(f"   - Role: {verifier_user.role}")
        print(f"   - Organization: {verifier_user.organization}")
        print(f"   - Is active: {verifier_user.is_active}")
        print(f"   - Is staff: {verifier_user.is_staff}")
        print(f"   - Is superuser: {verifier_user.is_superuser}")
        
        return verifier_user
    except User.DoesNotExist:
        print("❌ Verifier user not found!")
        return None


def check_verifier_role():
    """Check the verifier role's current state."""
    print("\n🔍 Checking Verifier Role...")
    
    try:
        organization = Organization.objects.get(name="Innovate Inc.")
        verifier_role = Role.objects.get(name="Verifier", organization=organization)
        print(f"✅ Found verifier role: {verifier_role.name}")
        print(f"   - Organization: {verifier_role.organization}")
        print(f"   - Permissions count: {verifier_role.permissions.count()}")
        
        # List all permissions
        permissions = verifier_role.permissions.all()
        print(f"   - Permissions:")
        for perm in permissions:
            print(f"     * {perm.codename} ({perm.content_type.app_label}.{perm.content_type.model})")
        
        return verifier_role
    except (Organization.DoesNotExist, Role.DoesNotExist) as e:
        print(f"❌ Verifier role not found: {e}")
        return None


def check_required_permissions():
    """Check if required verifier permissions exist."""
    print("\n🔍 Checking Required Permissions...")
    
    required_permissions = [
        'view_payment_verification_dashboard',
        'view_payment_analytics',
        'view_audit_logs',
        'verify_deal_payment',
        'verify_payments',
        'manage_invoices',
        'access_verification_queue',
        'manage_refunds',
        'view_all_deals',
        'view_all_clients',
        'view_paymentinvoice',
        'view_paymentapproval'
    ]
    
    existing_permissions = []
    missing_permissions = []
    
    for perm_codename in required_permissions:
        try:
            perm = Permission.objects.get(codename=perm_codename)
            existing_permissions.append(perm)
            print(f"✅ {perm_codename}")
        except Permission.DoesNotExist:
            missing_permissions.append(perm_codename)
            print(f"❌ {perm_codename} - NOT FOUND")
    
    print(f"\n📊 Summary:")
    print(f"   - Existing permissions: {len(existing_permissions)}")
    print(f"   - Missing permissions: {len(missing_permissions)}")
    
    return existing_permissions, missing_permissions


def check_user_permissions(user):
    """Check what permissions the user actually has."""
    print("\n🔍 Checking User Permissions...")
    
    if not user:
        print("❌ No user to check")
        return
    
    # Get all user permissions (including from groups and roles)
    user_permissions = user.user_permissions.all()
    role_permissions = user.role.permissions.all() if user.role else Permission.objects.none()
    
    print(f"   - Direct user permissions: {user_permissions.count()}")
    print(f"   - Role permissions: {role_permissions.count()}")
    
    # List role permissions
    if role_permissions:
        print(f"   - Role permissions:")
        for perm in role_permissions:
            print(f"     * {perm.codename} ({perm.content_type.app_label}.{perm.content_type.model})")
    else:
        print(f"   - No role permissions found")


def fix_verifier_permissions():
    """Attempt to fix verifier permissions."""
    print("\n🔧 Attempting to Fix Verifier Permissions...")
    
    try:
        # Get verifier user and role
        verifier_user = User.objects.get(username='verifier')
        organization = Organization.objects.get(name="Innovate Inc.")
        verifier_role = Role.objects.get(name="Verifier", organization=organization)
        
        # Assign user to role if not already assigned
        if verifier_user.role != verifier_role:
            verifier_user.role = verifier_role
            verifier_user.save()
            print("✅ Assigned verifier user to verifier role")
        else:
            print("✅ User already assigned to verifier role")
        
        # Run the permission assignment command
        from django.core.management import call_command
        call_command('assign_role_permissions', '--role', 'Verifier')
        print("✅ Ran assign_role_permissions command")
        
        # Check permissions again
        verifier_role.refresh_from_db()
        print(f"✅ Verifier role now has {verifier_role.permissions.count()} permissions")
        
    except Exception as e:
        print(f"❌ Error fixing permissions: {e}")


def main():
    """Main function."""
    print("🔍 Verifier Permissions Debug Script")
    print("=" * 50)
    
    # Check current state
    verifier_user = check_verifier_user()
    verifier_role = check_verifier_role()
    existing_permissions, missing_permissions = check_required_permissions()
    check_user_permissions(verifier_user)
    
    # Ask if user wants to fix permissions
    print("\n🤔 Would you like to attempt to fix the permissions? (y/n): ", end="")
    choice = input().strip().lower()
    
    if choice == 'y':
        fix_verifier_permissions()
        
        # Check state again after fix
        print("\n" + "=" * 50)
        print("🔍 Checking State After Fix...")
        verifier_user = check_verifier_user()
        verifier_role = check_verifier_role()
        check_user_permissions(verifier_user)
    
    print("\n✅ Debug completed!")


if __name__ == "__main__":
    main() 