#!/usr/bin/env python
import os
import django
import requests
import json

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from authentication.models import User
from rest_framework.authtoken.models import Token

def test_api_access():
    """Test API access for different user roles."""
    print("🧪 === API ACCESS TESTING ===")
    
    # Test users
    test_users = [
        ("sales@innovate.com", "password123", "Salesperson"),
        ("verifier@innovate.com", "password123", "Verifier"),
        ("orgadmin@innovate.com", "password123", "Organization Admin"),
    ]
    
    base_url = "https://backend-prs.onrender.com/api/v1"
    
    for email, password, role_name in test_users:
        print(f"\n👤 Testing {role_name} ({email}):")
        
        try:
            # Get or create token
            user = User.objects.get(email=email)
            token, created = Token.objects.get_or_create(user=user)
            
            if created:
                print(f"  ✅ Created new token for {email}")
            else:
                print(f"  ✅ Using existing token for {email}")
            
            headers = {
                "Authorization": f"Token {token.key}",
                "Content-Type": "application/json"
            }
            
            # Test endpoints based on role
            if role_name == "Salesperson":
                test_endpoints = [
                    ("GET", "/dashboard/dashboard/", "Dashboard"),
                    ("GET", "/clients/", "Clients"),
                    ("GET", "/deals/deals/", "Deals"),
                    ("GET", "/commission/", "Commission"),
                ]
            elif role_name == "Verifier":
                test_endpoints = [
                    ("GET", "/verifier/dashboard/", "Verifier Dashboard"),
                    ("GET", "/verifier/invoices/", "Invoices"),
                    ("GET", "/verifier/deals/", "Deals (Read-only)"),
                ]
            else:
                test_endpoints = [
                    ("GET", "/auth/users/", "User Management"),
                    ("GET", "/teams/", "Teams"),
                ]
            
            for method, endpoint, description in test_endpoints:
                try:
                    url = f"{base_url}{endpoint}"
                    response = requests.request(method, url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        print(f"  ✅ {description}: 200 OK")
                    elif response.status_code == 403:
                        print(f"  ❌ {description}: 403 Forbidden (Permission denied)")
                    elif response.status_code == 401:
                        print(f"  ❌ {description}: 401 Unauthorized (Authentication failed)")
                    else:
                        print(f"  ⚠️  {description}: {response.status_code} {response.reason}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"  ❌ {description}: Request failed - {e}")
                    
        except User.DoesNotExist:
            print(f"  ❌ User {email} not found!")
        except Exception as e:
            print(f"  ❌ Error testing {email}: {e}")
    
    print("\n🎉 API access testing completed!")

if __name__ == "__main__":
    test_api_access() 