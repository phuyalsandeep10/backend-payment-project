#!/usr/bin/env python3
"""
Script to check current tokens and their associated users
"""
import os
import sys
import django

# Add the backend directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from rest_framework.authtoken.models import Token
from authentication.models import User

def check_tokens():
    print("=== Token Analysis ===")
    print(f"Total tokens: {Token.objects.count()}")
    print(f"Total users: {User.objects.count()}")
    print()
    
    print("=== Active Tokens ===")
    for token in Token.objects.all():
        user = token.user
        print(f"Token: {token.key[:20]}...")
        print(f"  User: {user.email}")
        print(f"  Role: {user.role.name if user.role else 'No role'}")
        print(f"  Is Active: {user.is_active}")
        print(f"  Is Superuser: {user.is_superuser}")
        print()
    
    print("=== Users Without Tokens ===")
    users_without_tokens = User.objects.filter(auth_token__isnull=True)
    for user in users_without_tokens:
        print(f"User: {user.email}")
        print(f"  Role: {user.role.name if user.role else 'No role'}")
        print(f"  Is Active: {user.is_active}")
        print()

if __name__ == "__main__":
    check_tokens() 