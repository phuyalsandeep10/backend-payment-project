#!/usr/bin/env python3
"""
Test script to verify direct login functionality
"""

import requests
import json

# Test credentials from the initialization
test_users = [
    {"email": "admin@example.com", "password": "defaultpass", "role": "Super Admin"},
    {"email": "admin@techcorp.com", "password": "admin123", "role": "Organization Admin"},
    {"email": "manager@techcorp.com", "password": "manager123", "role": "Sales Manager"},
    {"email": "john.smith@techcorp.com", "password": "john123", "role": "Senior Salesperson"},
    {"email": "sarah.johnson@techcorp.com", "password": "sarah123", "role": "Salesperson"},
    {"email": "mike.davis@techcorp.com", "password": "mike123", "role": "Salesperson"},
]

def test_direct_login(base_url="http://localhost:8000"):
    """Test the direct login endpoint"""
    login_url = f"{base_url}/api/v1/auth/login/direct/"
    
    print("🧪 Testing Direct Login Endpoint")
    print("=" * 50)
    
    for user in test_users:
        print(f"\n👤 Testing login for {user['role']}: {user['email']}")
        
        try:
            response = requests.post(login_url, json={
                "email": user["email"],
                "password": user["password"]
            })
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Login successful!")
                print(f"   Token: {data.get('token', 'N/A')[:20]}...")
                print(f"   User ID: {data.get('user', {}).get('id', 'N/A')}")
                print(f"   Username: {data.get('user', {}).get('username', 'N/A')}")
                print(f"   Organization: {data.get('user', {}).get('organization_name', 'N/A')}")
            else:
                print(f"❌ Login failed: {response.status_code}")
                print(f"   Response: {response.text}")
                
        except requests.exceptions.ConnectionError:
            print(f"🔌 Connection failed - server not running at {base_url}")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

def test_render_deployment():
    """Test the Render deployment"""
    render_url = "https://backend-prs.onrender.com"
    print(f"\n🌐 Testing Render Deployment: {render_url}")
    print("=" * 50)
    
    # Test a simple user first
    test_user = {"email": "admin@techcorp.com", "password": "admin123", "role": "Organization Admin"}
    
    login_url = f"{render_url}/api/v1/auth/login/direct/"
    
    print(f"👤 Testing login for {test_user['role']}: {test_user['email']}")
    
    try:
        response = requests.post(login_url, json={
            "email": test_user["email"],
            "password": test_user["password"]
        }, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Render deployment login successful!")
            print(f"   Token: {data.get('token', 'N/A')[:20]}...")
            print(f"   User ID: {data.get('user', {}).get('id', 'N/A')}")
            print(f"   Username: {data.get('user', {}).get('username', 'N/A')}")
            print(f"   Organization: {data.get('user', {}).get('organization_name', 'N/A')}")
        else:
            print(f"❌ Render login failed: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except requests.exceptions.Timeout:
        print(f"⏰ Request timed out - Render service may be sleeping")
    except requests.exceptions.ConnectionError:
        print(f"🔌 Connection failed to Render deployment")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("🚀 PRS Authentication Test Suite")
    print("=" * 50)
    
    # Test local development server
    test_direct_login()
    
    # Test Render deployment
    test_render_deployment()
    
    print("\n📋 Summary:")
    print("- Use /api/v1/auth/login/direct/ for direct login without OTP")
    print("- Use /api/v1/auth/login/ for OTP-based login")
    print("- All TechCorp users should be able to login with their credentials")
    print("- The system now has proper default roles and permissions") 