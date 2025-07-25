#!/usr/bin/env python3
"""
Comprehensive logical error checker for PRS system
"""
import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.contrib.auth.models import Permission
from django.db import connection, models
from authentication.models import User
from permissions.models import Role

def check_database_consistency():
    """Check for database consistency issues"""
    print("🔍 CHECKING DATABASE CONSISTENCY")
    print("=" * 50)
    
    issues = []
    
    try:
        # Check for users without roles
        users_no_role = User.objects.filter(role__isnull=True).count()
        if users_no_role > 0:
            issues.append(f"Found {users_no_role} users without roles")
        
        # Check for duplicate emails
        duplicate_emails = User.objects.values('email').annotate(
            count=models.Count('email')
        ).filter(count__gt=1)
        if duplicate_emails.exists():
            issues.append(f"Found {duplicate_emails.count()} duplicate email addresses")
        
        # Check for inactive superusers
        inactive_superusers = User.objects.filter(is_superuser=True, is_active=False).count()
        if inactive_superusers > 0:
            issues.append(f"Found {inactive_superusers} inactive superuser accounts")
            
    except Exception as e:
        issues.append(f"Database consistency check failed: {e}")
    
    return issues

def check_permission_logic():
    """Check for permission system logical errors"""
    print("🔍 CHECKING PERMISSION LOGIC")
    print("=" * 50)
    
    issues = []
    
    try:
        # Check if Super Admin role exists
        super_admin_roles = Role.objects.filter(name='Super Admin')
        if not super_admin_roles.exists():
            issues.append("No Super Admin role found")
        elif super_admin_roles.count() > 1:
            issues.append(f"Multiple Super Admin roles found ({super_admin_roles.count()})")
        
        # Check for roles without permissions
        roles_no_perms = Role.objects.filter(permissions__isnull=True).count()
        if roles_no_perms > 0:
            issues.append(f"Found {roles_no_perms} roles without any permissions")
        
        # Check for superuser accounts
        superuser_count = User.objects.filter(is_superuser=True, is_active=True).count()
        if superuser_count == 0:
            issues.append("No active superuser accounts found - system may be inaccessible")
            
    except Exception as e:
        issues.append(f"Permission logic check failed: {e}")
    
    return issues

def check_configuration_logic():
    """Check for configuration logical errors"""
    print("🔍 CHECKING CONFIGURATION LOGIC")
    print("=" * 50)
    
    issues = []
    
    # Check environment variables
    required_env_vars = ['SECRET_KEY']
    for var in required_env_vars:
        if not os.getenv(var):
            issues.append(f"Missing required environment variable: {var}")
    
    # Check DEBUG setting in production
    if os.getenv('DEBUG', '').lower() == 'true' and os.getenv('RENDER'):
        issues.append("DEBUG=True in production environment (security risk)")
    
    # Check database connection logic
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception as e:
        issues.append(f"Database connection logic error: {e}")
    
    return issues

def main():
    """Run all logical error checks"""
    print("🚀 PRS SYSTEM LOGICAL ERROR CHECKER")
    print("=" * 60)
    
    all_issues = []
    
    # Run all checks
    checks = [
        ("Database Consistency", check_database_consistency),
        ("Permission Logic", check_permission_logic),
        ("Configuration Logic", check_configuration_logic),
    ]
    
    for check_name, check_func in checks:
        try:
            issues = check_func()
            if issues:
                print(f"\n❌ {check_name} Issues Found:")
                for issue in issues:
                    print(f"   - {issue}")
                all_issues.extend(issues)
            else:
                print(f"\n✅ {check_name}: No issues found")
        except Exception as e:
            error_msg = f"{check_name} check failed: {e}"
            print(f"\n⚠️  {error_msg}")
            all_issues.append(error_msg)
    
    # Summary
    print(f"\n📊 SUMMARY")
    print("=" * 50)
    if all_issues:
        print(f"❌ Found {len(all_issues)} logical errors:")
        for i, issue in enumerate(all_issues, 1):
            print(f"   {i}. {issue}")
        print(f"\n🔧 Run fixes with: python fix_critical_logic_errors.py")
        return 1
    else:
        print("✅ No logical errors detected!")
        return 0

if __name__ == '__main__':
    sys.exit(main())