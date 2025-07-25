#!/usr/bin/env python3
"""
Fix critical logical errors in PRS system
"""
import os
import sys
import django

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

def fix_orphaned_data():
    """Fix orphaned data relationships"""
    from deals.models import Deal
    from clients.models import Client
    
    # Fix deals without clients
    orphaned_deals = Deal.objects.filter(client__isnull=True)
    if orphaned_deals.exists():
        print(f"⚠️  Found {orphaned_deals.count()} orphaned deals")
        # Create a default client or delete orphaned deals
        default_client, created = Client.objects.get_or_create(
            name="Default Client",
            defaults={'email': 'default@example.com'}
        )
        orphaned_deals.update(client=default_client)
        print(f"✅ Fixed {orphaned_deals.count()} orphaned deals")
    else:
        print("✅ No orphaned deals found")
        
def fix_permission_assignments():
    """Ensure all users have proper role assignments"""
    from authentication.models import User
    from permissions.models import Role
    
    users_without_roles = User.objects.filter(role__isnull=True)
    if users_without_roles.exists():
        print(f"⚠️  Found {users_without_roles.count()} users without roles")
        
        # Get or create default role (without description field)
        default_role, created = Role.objects.get_or_create(
            name="Default User"
        )
        
        if created:
            print("✅ Created 'Default User' role")
        
        # Assign default role to users without roles
        users_without_roles.update(role=default_role)
        print(f"✅ Assigned default role to {users_without_roles.count()} users")
    else:
        print("✅ All users have role assignments")

def validate_business_constraints():
    """Validate business logic constraints"""
    from deals.models import Deal
    
    # Check for negative deal values
    invalid_deals = Deal.objects.filter(deal_value__lt=0)
    if invalid_deals.exists():
        print(f"⚠️  Found {invalid_deals.count()} deals with negative values")
        # Set negative values to 0 or delete invalid deals
        invalid_deals.update(deal_value=0)
        print(f"✅ Fixed {invalid_deals.count()} deals with negative values")
    else:
        print("✅ No deals with negative values found")
    
    # Check for deals without verification status
    deals_no_status = Deal.objects.filter(verification_status__isnull=True)
    if deals_no_status.exists():
        print(f"⚠️  Found {deals_no_status.count()} deals without verification status")
        deals_no_status.update(verification_status='pending')
        print(f"✅ Set pending status for {deals_no_status.count()} deals")
    else:
        print("✅ All deals have verification status")

def check_database_integrity():
    """Check database integrity"""
    from django.db import connection
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        print("✅ Database connection is working")
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return False
    
    return True

def check_critical_permissions():
    """Check if critical permissions exist"""
    from django.contrib.auth.models import Permission
    from permissions.models import Role
    
    # Check if Super Admin role exists
    super_admin_roles = Role.objects.filter(name='Super Admin')
    if not super_admin_roles.exists():
        print("⚠️  No Super Admin role found")
        return False
    
    print("✅ Super Admin role exists")
    return True

if __name__ == '__main__':
    print("🔧 Fixing critical logical errors...")
    print("=" * 50)
    
    # Check database connection first
    if not check_database_integrity():
        print("❌ Cannot proceed - database connection failed")
        sys.exit(1)
    
    # Run fixes
    try:
        fix_orphaned_data()
        fix_permission_assignments()
        validate_business_constraints()
        check_critical_permissions()
        
        print("\n✅ Critical logic error fixes completed!")
        print("🔍 Run comprehensive checks with: python manage.py check")
        
    except Exception as e:
        print(f"❌ Error during fixes: {e}")
        sys.exit(1)
