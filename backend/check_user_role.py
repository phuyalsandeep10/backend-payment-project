#!/usr/bin/env python
import os
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from authentication.models import User
from organization.models import Organization

def check_user_role():
    email = "shishirkafle1@gmail.com"
    try:
        user = User.objects.get(email=email)
        print(f"✅ User found: {user.email}")
        print(f"   Name: {user.first_name} {user.last_name}")
        print(f"   Is active: {user.is_active}")
        print(f"   Is superuser: {user.is_superuser}")
        if hasattr(user, 'role') and user.role:
            print(f"   Role: {user.role.name}")
            print(f"   Role organization: {user.role.organization.name if user.role.organization else 'None'}")
            print(f"   Permissions:")
            for perm in user.role.permissions.all():
                print(f"      - {perm.codename}")
        else:
            print("   ❌ No role assigned")
        if hasattr(user, 'organization') and user.organization:
            print(f"   Organization: {user.organization.name} (ID: {user.organization.id})")
        else:
            print("   ❌ No organization assigned")
    except User.DoesNotExist:
        print(f"❌ User with email '{email}' not found")

if __name__ == "__main__":
    check_user_role() 