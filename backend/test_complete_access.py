#!/usr/bin/env python
"""
Complete Access Test Script
Tests that all users have proper access to their respective dashboards and endpoints.
"""

import os
import sys
import django

# Add the backend directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.contrib.auth.models import Permission
from authentication.models import User
from permissions.models import Role
from organization.models import Organization


def test_user_access():
    """Test that all users have proper access."""
    print("🔍 Testing User Access and Permissions")
    print("=" * 50)
    
    try:
        organization = Organization.objects.get(name="Innovate Inc.")
        
        # Test users
        test_users = {
            'superadmin': 'Super Admin',
            'orgadmin': 'Organization Admin', 
            'salestest': 'Salesperson',
            'verifier': 'Verifier'
        }
        
        for username, expected_role in test_users.items():
            try:
                user = User.objects.get(username=username)
                print(f"\n👤 Testing {username}:")
                print(f"  - Role: {user.role.name if user.role else 'None'}")
                print(f"  - Organization: {user.organization.name if user.organization else 'None'}")
                print(f"  - Is Active: {user.is_active}")
                print(f"  - Is Superuser: {user.is_superuser}")
                print(f"  - Is Staff: {user.is_staff}")
                
                # Check role assignment
                if user.role and user.role.name == expected_role:
                    print(f"  ✅ Role correctly assigned")
                else:
                    print(f"  ❌ Role mismatch: expected {expected_role}, got {user.role.name if user.role else 'None'}")
                
                # Check permissions
                if user.role:
                    permission_count = user.role.permissions.count()
                    print(f"  - Permissions count: {permission_count}")
                    
                    if permission_count > 0:
                        print(f"  ✅ Has permissions")
                        
                        # Show key permissions for each role
                        if expected_role == 'Verifier':
                            key_perms = ['view_payment_verification_dashboard', 'verify_deal_payment', 'view_audit_logs']
                        elif expected_role == 'Salesperson':
                            key_perms = ['view_own_deals', 'create_deal', 'view_commission']
                        elif expected_role == 'Organization Admin':
                            key_perms = ['add_user', 'view_all_deals', 'manage_invoices']
                        else:  # Super Admin
                            key_perms = ['add_user', 'add_deal', 'add_client']
                        
                        for perm_name in key_perms:
                            has_perm = user.role.permissions.filter(codename=perm_name).exists()
                            status = "✅" if has_perm else "❌"
                            print(f"    {status} {perm_name}")
                    else:
                        print(f"  ❌ No permissions assigned")
                else:
                    print(f"  ❌ No role assigned")
                    
            except User.DoesNotExist:
                print(f"  ❌ User '{username}' not found")
            except Exception as e:
                print(f"  ❌ Error testing {username}: {e}")
    
    except Organization.DoesNotExist:
        print("❌ Organization 'Innovate Inc.' not found")
    except Exception as e:
        print(f"❌ Error: {e}")


def test_role_permissions():
    """Test that all roles have the correct permissions."""
    print("\n🔐 Testing Role Permissions")
    print("=" * 50)
    
    try:
        organization = Organization.objects.get(name="Innovate Inc.")
        
        # Expected permission counts for each role
        expected_counts = {
            'Super Admin': 146,  # All permissions
            'Organization Admin': 69,
            'Salesperson': 25,
            'Verifier': 20
        }
        
        for role_name, expected_count in expected_counts.items():
            try:
                role = Role.objects.get(name=role_name, organization=organization)
                actual_count = role.permissions.count()
                
                print(f"\n🎭 {role_name}:")
                print(f"  - Expected permissions: {expected_count}")
                print(f"  - Actual permissions: {actual_count}")
                
                if actual_count == expected_count:
                    print(f"  ✅ Permission count matches")
                else:
                    print(f"  ❌ Permission count mismatch")
                
                # Show some key permissions
                print(f"  - Key permissions:")
                key_permissions = role.permissions.all()[:5]
                for perm in key_permissions:
                    print(f"    • {perm.codename}")
                
            except Role.DoesNotExist:
                print(f"  ❌ Role '{role_name}' not found")
            except Exception as e:
                print(f"  ❌ Error testing {role_name}: {e}")
    
    except Organization.DoesNotExist:
        print("❌ Organization 'Innovate Inc.' not found")
    except Exception as e:
        print(f"❌ Error: {e}")


def test_verifier_specific_permissions():
    """Test that verifier has all required permissions."""
    print("\n🔍 Testing Verifier-Specific Permissions")
    print("=" * 50)
    
    try:
        organization = Organization.objects.get(name="Innovate Inc.")
        verifier_role = Role.objects.get(name="Verifier", organization=organization)
        
        # Required verifier permissions
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
            'view_own_deals',
            'view_all_clients',
            'view_own_clients'
        ]
        
        print(f"🎭 Verifier Role Permissions:")
        print(f"  - Total permissions: {verifier_role.permissions.count()}")
        
        missing_permissions = []
        for perm_name in required_permissions:
            has_perm = verifier_role.permissions.filter(codename=perm_name).exists()
            status = "✅" if has_perm else "❌"
            print(f"  {status} {perm_name}")
            
            if not has_perm:
                missing_permissions.append(perm_name)
        
        if missing_permissions:
            print(f"\n❌ Missing permissions: {', '.join(missing_permissions)}")
        else:
            print(f"\n✅ All required verifier permissions are present!")
    
    except Exception as e:
        print(f"❌ Error testing verifier permissions: {e}")


def main():
    """Main function."""
    print("🔧 Complete Access Test")
    print("=" * 50)
    
    test_user_access()
    test_role_permissions()
    test_verifier_specific_permissions()
    
    print("\n✅ Access test completed!")


if __name__ == "__main__":
    main() 