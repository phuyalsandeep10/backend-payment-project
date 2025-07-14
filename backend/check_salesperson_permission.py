#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from permissions.models import Role
from django.contrib.auth.models import Permission
from organization.models import Organization

ROLE_NAME = 'Salesperson'
PERM_CODENAME = 'create_deal_payment'

# Optionally, you can scope to a specific organization
ORG_NAME = None  # Set to None to check all, or to a string to filter

def main():
    if ORG_NAME:
        orgs = Organization.objects.filter(name=ORG_NAME)
    else:
        orgs = Organization.objects.all()

    for org in orgs:
        print(f"\nChecking organization: {org.name}")
        try:
            role = Role.objects.get(name=ROLE_NAME, organization=org)
        except Role.DoesNotExist:
            print(f"❌ Role '{ROLE_NAME}' does not exist in organization '{org.name}'")
            continue

        if role.permissions.filter(codename=PERM_CODENAME).exists():
            print(f"✅ '{ROLE_NAME}' already has '{PERM_CODENAME}' permission in '{org.name}'")
        else:
            print(f"⏳ Adding '{PERM_CODENAME}' permission to '{ROLE_NAME}' in '{org.name}'...")
            try:
                perm = Permission.objects.get(codename=PERM_CODENAME)
                role.permissions.add(perm)
                print(f"✅ Added '{PERM_CODENAME}' permission to '{ROLE_NAME}' in '{org.name}'")
            except Permission.DoesNotExist:
                print(f"❌ Permission '{PERM_CODENAME}' does not exist. Please create it in the admin or via migration.")

if __name__ == "__main__":
    main() 