#!/usr/bin/env python
"""
Test script for unified login functionality
"""
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from authentication.models import User
from permissions.models import Role
from organization.models import Organization
import json

User = get_user_model()

def test_unified_login():
    """Test the unified login functionality"""
    print("Testing unified login functionality...")
    
    # Create test client
    client = APIClient()
    
    # Create test organization
    org, created = Organization.objects.get_or_create(
        name="Test Organization",
        defaults={'created_by': None}
    )
    
    # Create test roles
    super_admin_role, _ = Role.objects.get_or_create(
        name="Super Admin",
        organization=None
    )
    
    org_admin_role, _ = Role.objects.get_or_create(
        name="Organization Admin",
        organization=org
    )
    
    salesperson_role, _ = Role.objects.get_or_create(
        name="Salesperson",
        organization=org
    )
    
    # Create test users
    super_admin = User.objects.create_user(
        email="superadmin@test.com",
        password="testpass123",
        first_name="Super",
        last_name="Admin",
        is_superuser=True,
        role=super_admin_role
    )
    
    org_admin = User.objects.create_user(
        email="orgadmin@test.com",
        password="testpass123",
        first_name="Org",
        last_name="Admin",
        organization=org,
        role=org_admin_role
    )
    
    salesperson = User.objects.create_user(
        email="salesperson@test.com",
        password="testpass123",
        first_name="Sales",
        last_name="Person",
        organization=org,
        role=salesperson_role
    )
    
    print(f"Created test users:")
    print(f"- Super Admin: {super_admin.email}")
    print(f"- Org Admin: {org_admin.email}")
    print(f"- Salesperson: {salesperson.email}")
    
    # Test 1: Super Admin login (should require OTP)
    print("\n1. Testing Super Admin login...")
    response = client.post('/auth/login/', {
        'email': 'superadmin@test.com',
        'password': 'testpass123'
    })
    
    print(f"Response status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        if data.get('requires_otp'):
            print("✓ Super Admin correctly requires OTP")
        else:
            print("✗ Super Admin should require OTP")
    else:
        print(f"✗ Super Admin login failed: {response.content}")
    
    # Test 2: Org Admin login (should require OTP)
    print("\n2. Testing Org Admin login...")
    response = client.post('/auth/login/', {
        'email': 'orgadmin@test.com',
        'password': 'testpass123'
    })
    
    print(f"Response status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        if data.get('requires_otp'):
            print("✓ Org Admin correctly requires OTP")
        else:
            print("✗ Org Admin should require OTP")
    else:
        print(f"✗ Org Admin login failed: {response.content}")
    
    # Test 3: Salesperson login (should provide direct token)
    print("\n3. Testing Salesperson login...")
    response = client.post('/auth/login/', {
        'email': 'salesperson@test.com',
        'password': 'testpass123'
    })
    
    print(f"Response status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        if data.get('token') and not data.get('requires_otp'):
            print("✓ Salesperson correctly gets direct token")
        else:
            print("✗ Salesperson should get direct token")
    else:
        print(f"✗ Salesperson login failed: {response.content}")
    
    # Test 4: Invalid credentials
    print("\n4. Testing invalid credentials...")
    response = client.post('/auth/login/', {
        'email': 'nonexistent@test.com',
        'password': 'wrongpass'
    })
    
    print(f"Response status: {response.status_code}")
    if response.status_code == 401:
        print("✓ Invalid credentials correctly rejected")
    else:
        print(f"✗ Invalid credentials should be rejected: {response.content}")
    
    print("\nTest completed!")

if __name__ == "__main__":
    test_unified_login() 