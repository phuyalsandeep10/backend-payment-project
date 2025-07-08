#!/usr/bin/env python3
"""
Verify Django Server Script

This script helps verify that your Django server is running and accessible
through the VS Code dev tunnel.
"""

import requests
import sys
import time
from urllib.parse import urljoin

def check_local_server():
    """Check if Django server is running locally"""
    print("🔍 Checking local Django server...")
    
    try:
        response = requests.get("http://localhost:8000/api/v1/", timeout=5)
        if response.status_code in [200, 401, 403]:
            print("✅ Local Django server is running on port 8000")
            return True
        else:
            print(f"⚠️  Local server responded with status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Local Django server is NOT running on port 8000")
        print("   Please start the server with: python manage.py runserver")
        return False
    except Exception as e:
        print(f"❌ Error checking local server: {str(e)}")
        return False

def check_tunnel_access(tunnel_url):
    """Check if tunnel is accessible"""
    print(f"\n🔍 Checking tunnel access: {tunnel_url}")
    
    try:
        # Test basic connectivity
        response = requests.get(f"{tunnel_url}api/v1/", timeout=10)
        if response.status_code in [200, 401, 403]:
            print("✅ Tunnel is accessible")
            return True
        else:
            print(f"⚠️  Tunnel responded with status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to tunnel")
        return False
    except Exception as e:
        print(f"❌ Error checking tunnel: {str(e)}")
        return False

def check_health_endpoint(tunnel_url):
    """Check health endpoint"""
    print(f"\n🔍 Checking health endpoint...")
    
    try:
        response = requests.get(f"{tunnel_url}api/v1/auth/health/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print("✅ Health endpoint is working")
            print(f"   Status: {data.get('status')}")
            print(f"   Message: {data.get('message')}")
            return True
        else:
            print(f"⚠️  Health endpoint returned status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error checking health endpoint: {str(e)}")
        return False

def main():
    print("🚀 Django Server Verification")
    print("=" * 50)
    
    # Check if tunnel URL is provided
    tunnel_url = None
    if len(sys.argv) > 1:
        tunnel_url = sys.argv[1]
        if not tunnel_url.endswith('/'):
            tunnel_url += '/'
    
    # Step 1: Check local server
    local_ok = check_local_server()
    
    if not local_ok:
        print("\n🔧 To fix this:")
        print("1. Make sure you're in the backend directory")
        print("2. Run: python manage.py runserver")
        print("3. Wait for the server to start")
        print("4. Run this script again")
        return
    
    # Step 2: Check tunnel if URL provided
    if tunnel_url:
        tunnel_ok = check_tunnel_access(tunnel_url)
        if tunnel_ok:
            check_health_endpoint(tunnel_url)
        else:
            print("\n🔧 Tunnel issues:")
            print("1. Check if VS Code tunnel is active")
            print("2. Verify the tunnel URL is correct")
            print("3. Make sure tunnel is configured for port 8000")
    else:
        print("\n📝 To test tunnel access, provide the tunnel URL:")
        print("   python verify_server.py https://your-tunnel-url.inc1.devtunnels.ms")
    
    print("\n" + "=" * 50)
    if local_ok:
        print("✅ Django server is running locally!")
        if tunnel_url:
            print("📋 Share this URL with your colleague:")
            print(f"   {tunnel_url}api/v1/")
            print(f"   Health check: {tunnel_url}api/v1/auth/health/")
    else:
        print("❌ Please start the Django server first")

if __name__ == "__main__":
    main() 