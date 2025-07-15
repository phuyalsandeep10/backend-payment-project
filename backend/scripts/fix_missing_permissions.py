#!/usr/bin/env python
"""
Fix Missing Permissions Script
Identifies and creates missing permissions, then ensures all roles have complete permission sets.
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


def check_missing_permissions():
    """Check what permissions are missing."""
    print("🔍 Checking for missing permissions...")
    
    # Define required permissions for each role
    required_permissions = {
        "Organization Admin": [
            'add_user', 'change_user', 'delete_user', 'view_user',
            'add_client', 'change_client', 'delete_client', 'view_client',
            'add_deal', 'change_deal', 'delete_deal', 'view_deal',
            'add_project', 'change_project', 'delete_project', 'view_project',
            'add_team', 'change_team', 'delete_team', 'view_team',
            'add_commission', 'change_commission', 'delete_commission', 'view_commission',
            'view_all_clients', 'view_own_clients', 'create_new_client', 'edit_client_details', 'remove_client',
            'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 'log_deal_activity',
            'verify_deal_payment', 'verify_payments', 'manage_invoices', 'access_verification_queue', 'manage_refunds',
            'view_all_projects', 'view_own_projects', 'create_project', 'edit_project', 'delete_project',
            'view_all_teams', 'view_own_teams', 'create_new_team', 'edit_team_details', 'remove_team',
            'view_all_commissions', 'create_commission', 'edit_commission',
            'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
            'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
            'add_notification', 'change_notification', 'delete_notification', 'view_notification',
            'view_audit_logs', 'view_payment_verification_dashboard', 'view_payment_analytics',
            'can_manage_roles'
        ],
        "Salesperson": [
            'view_own_clients', 'create_new_client', 'edit_client_details', 'remove_client',
            'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 'delete_deal', 'log_deal_activity',
            'view_all_projects', 'view_own_projects', 'create_project', 'edit_project', 'delete_project',
            'view_all_teams', 'view_own_teams', 'create_new_team', 'edit_team_details', 'remove_team',
            'view_commission', 'view_all_commissions', 'create_commission', 'edit_commission',
            'create_deal_payment', 'add_payment', 'view_payment', 'change_payment', 'delete_payment',
            'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
            'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
            'add_dailystreakrecord', 'view_dailystreakrecord', 'change_dailystreakrecord', 'delete_dailystreakrecord'
        ],
        "Verifier": [
            'view_payment_verification_dashboard', 'view_payment_analytics', 'view_audit_logs',
            'verify_deal_payment', 'verify_payments', 'manage_invoices', 'access_verification_queue', 'manage_refunds',
            'view_all_deals', 'view_own_deals', 'view_all_clients', 'view_own_clients',
            'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
            'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval'
        ]
    }
    
    missing_permissions = {}
    existing_permissions = {}
    
    for role_name, permissions in required_permissions.items():
        missing_permissions[role_name] = []
        existing_permissions[role_name] = []
        
        for perm_codename in permissions:
            try:
                # Use filter().first() to handle duplicates
                perm = Permission.objects.filter(codename=perm_codename).first()
                if perm:
                    existing_permissions[role_name].append(perm_codename)
                else:
                    missing_permissions[role_name].append(perm_codename)
            except Exception as e:
                print(f"  ⚠️  Error checking permission '{perm_codename}': {e}")
                missing_permissions[role_name].append(perm_codename)
    
    return missing_permissions, existing_permissions


def create_missing_permissions():
    """Create missing permissions."""
    print("🔧 Creating missing permissions...")
    
    # Define permissions to create with their content types
    permissions_to_create = {
        'add_user': 'authentication.user',
        'change_user': 'authentication.user',
        'delete_user': 'authentication.user',
        'view_user': 'authentication.user',
        'create_deal_payment': 'deals.payment',
        'add_payment': 'deals.payment',
        'view_payment': 'deals.payment',
        'change_payment': 'deals.payment',
        'delete_payment': 'deals.payment',
        'add_dailystreakrecord': 'Sales_dashboard.dailystreakrecord',
        'view_dailystreakrecord': 'Sales_dashboard.dailystreakrecord',
        'change_dailystreakrecord': 'Sales_dashboard.dailystreakrecord',
        'delete_dailystreakrecord': 'Sales_dashboard.dailystreakrecord'
    }
    
    created_count = 0
    
    for codename, content_type_str in permissions_to_create.items():
        try:
            # Check if permission already exists
            existing = Permission.objects.filter(codename=codename).first()
            if existing:
                print(f"  ✅ {codename} already exists")
                continue
            
            # Parse content type
            app_label, model_name = content_type_str.split('.')
            content_type = ContentType.objects.get(app_label=app_label, model=model_name)
            
            # Create permission
            permission = Permission.objects.create(
                codename=codename,
                name=f"Can {codename.replace('_', ' ')}",
                content_type=content_type
            )
            print(f"  ✅ Created {codename}")
            created_count += 1
            
        except Exception as e:
            print(f"  ❌ Failed to create {codename}: {e}")
    
    print(f"✅ Created {created_count} new permissions")
    return created_count


def assign_complete_permissions():
    """Assign complete permission sets to all roles."""
    print("🔐 Assigning complete permissions to roles...")
    
    try:
        organization = Organization.objects.get(name="Innovate Inc.")
        
        # Define complete permission sets for each role
        role_permissions = {
            "Organization Admin": [
                # User management
                'add_user', 'change_user', 'delete_user', 'view_user',
                # Client management
                'add_client', 'change_client', 'delete_client', 'view_client',
                'view_all_clients', 'view_own_clients', 'create_new_client', 'edit_client_details', 'remove_client',
                # Deal management
                'add_deal', 'change_deal', 'delete_deal', 'view_deal',
                'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 'log_deal_activity',
                'verify_deal_payment', 'verify_payments', 'manage_invoices', 'access_verification_queue', 'manage_refunds',
                # Project management
                'add_project', 'change_project', 'delete_project', 'view_project',
                'view_all_projects', 'view_own_projects', 'create_project', 'edit_project', 'delete_project',
                # Team management
                'add_team', 'change_team', 'delete_team', 'view_team',
                'view_all_teams', 'view_own_teams', 'create_new_team', 'edit_team_details', 'remove_team',
                # Commission management
                'add_commission', 'change_commission', 'delete_commission', 'view_commission',
                'view_all_commissions', 'create_commission', 'edit_commission',
                # Payment management
                'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
                'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
                # Notifications
                'add_notification', 'change_notification', 'delete_notification', 'view_notification',
                # Dashboard
                'view_audit_logs', 'view_payment_verification_dashboard', 'view_payment_analytics',
                # Role management
                'can_manage_roles'
            ],
            "Salesperson": [
                # Client permissions
                'view_own_clients', 'create_new_client', 'edit_client_details', 'remove_client',
                # Deal permissions
                'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 'delete_deal', 'log_deal_activity',
                # Project permissions
                'view_all_projects', 'view_own_projects', 'create_project', 'edit_project', 'delete_project',
                # Team permissions
                'view_all_teams', 'view_own_teams', 'create_new_team', 'edit_team_details', 'remove_team',
                # Commission permissions
                'view_commission', 'view_all_commissions', 'create_commission', 'edit_commission',
                # Payment permissions
                'create_deal_payment', 'add_payment', 'view_payment', 'change_payment', 'delete_payment',
                'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
                'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
                # Dashboard permissions
                'add_dailystreakrecord', 'view_dailystreakrecord', 'change_dailystreakrecord', 'delete_dailystreakrecord'
            ],
            "Verifier": [
                # Core verifier permissions
                'view_payment_verification_dashboard', 'view_payment_analytics', 'view_audit_logs',
                'verify_deal_payment', 'verify_payments', 'manage_invoices', 'access_verification_queue', 'manage_refunds',
                # Deal viewing permissions
                'view_all_deals', 'view_own_deals',
                # Client viewing permissions
                'view_all_clients', 'view_own_clients',
                # Payment management
                'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
                'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval'
            ]
        }
        
        for role_name, permission_codenames in role_permissions.items():
            try:
                role = Role.objects.get(name=role_name, organization=organization)
                print(f"\n🔧 Assigning permissions to {role_name}...")
                
                # Clear existing permissions
                role.permissions.clear()
                
                # Get permissions that exist
                permissions_to_add = []
                for codename in permission_codenames:
                    try:
                        # Use filter().first() to handle duplicates
                        perm = Permission.objects.filter(codename=codename).first()
                        if perm:
                            permissions_to_add.append(perm)
                        else:
                            print(f"  ⚠️  Permission '{codename}' not found, skipping")
                    except Exception as e:
                        print(f"  ⚠️  Error getting permission '{codename}': {e}")
                
                # Add permissions
                if permissions_to_add:
                    role.permissions.add(*permissions_to_add)
                    print(f"  ✅ Assigned {len(permissions_to_add)} permissions to {role_name}")
                else:
                    print(f"  ❌ No permissions found for {role_name}")
                    
            except Role.DoesNotExist:
                print(f"  ❌ Role '{role_name}' not found")
            except Exception as e:
                print(f"  ❌ Error assigning permissions to {role_name}: {e}")
    
    except Organization.DoesNotExist:
        print("❌ Organization 'Innovate Inc.' not found")
    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    """Main function."""
    print("🔧 Fix Missing Permissions Script")
    print("=" * 50)
    
    # Check missing permissions
    missing_permissions, existing_permissions = check_missing_permissions()
    
    print("\n📊 Missing Permissions Summary:")
    for role_name, missing in missing_permissions.items():
        if missing:
            print(f"  {role_name}: {len(missing)} missing permissions")
            for perm in missing:
                print(f"    - {perm}")
        else:
            print(f"  {role_name}: ✅ All permissions present")
    
    # Create missing permissions
    if any(missing_permissions.values()):
        print(f"\n🔧 Creating {sum(len(missing) for missing in missing_permissions.values())} missing permissions...")
        create_missing_permissions()
    else:
        print("\n✅ No missing permissions found")
    
    # Assign complete permissions
    print("\n🔐 Assigning complete permissions to roles...")
    assign_complete_permissions()
    
    print("\n✅ Permission fix completed!")


if __name__ == "__main__":
    main() 