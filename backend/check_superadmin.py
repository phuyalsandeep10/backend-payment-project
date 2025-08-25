#!/usr/bin/env python3

import os
import sys
import django

# Add the project root to Python path
sys.path.append('/Users/shishirkafle/Desktop/Frontend/Backend_PRS/backend')

# Set Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

# Configure Django
django.setup()

# Now import Django modules
from apps.authentication.models import User

try:
    # Check superadmin user
    user = User.objects.filter(username='superadmin').first()
    if user:
        print(f"✅ Superadmin user found")
        print(f"   Username: {user.username}")
        print(f"   Email: {user.email}")
        print(f"   is_superuser: {user.is_superuser}")
        print(f"   is_staff: {user.is_staff}")
        print(f"   is_active: {user.is_active}")
        print(f"   Role: {user.role}")
        print(f"   Organization: {user.organization}")
        
        if not user.is_superuser:
            print("❌ User does not have is_superuser=True")
            # Fix it
            user.is_superuser = True
            user.is_staff = True
            user.save()
            print("✅ Fixed: Set is_superuser=True and is_staff=True")
        else:
            print("✅ User has proper superuser permissions")
            
    else:
        print("❌ Superadmin user not found")
        
except Exception as e:
    print(f"❌ Error: {e}")