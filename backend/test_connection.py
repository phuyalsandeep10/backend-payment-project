#!/usr/bin/env python3
"""
Test API Connection Script

This script helps you test API connectivity from different URLs
to ensure your frontend can connect to the backend properly.
"""

import requests
import sys
import time
from urllib.parse import urljoin

def test_api_connection(base_url, endpoint="auth/"):
    """Test API connection to a given URL"""
    try:
        url = urljoin(base_url, f"api/v1/{endpoint}")
        print(f"🔍 Testing: {url}")
        
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            print(f"✅ SUCCESS: {response.status_code}")
            return True
        elif response.status_code == 401:
            print(f"✅ SUCCESS (Authentication required): {response.status_code}")
            return True
        elif response.status_code == 403:
            print(f"✅ SUCCESS (Forbidden - expected for auth endpoint): {response.status_code}")
            return True
        else:
            print(f"❌ FAILED: {response.status_code}")
            print(f"   Response: {response.text[:200]}...")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"❌ CONNECTION ERROR: Cannot connect to {url}")
        return False
    except requests.exceptions.Timeout:
        print(f"❌ TIMEOUT: Request timed out for {url}")
        return False
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return False

def main():
    print("🌐 API Connection Tester")
    print("=" * 50)
    
    # Test URLs
    test_urls = [
        "http://localhost:8000/",
        "http://127.0.0.1:8000/",
        "https://localhost:8000/",
        "https://127.0.0.1:8000/",
    ]
    
    # Add VS Code tunnel URL if provided
    if len(sys.argv) > 1:
        tunnel_url = sys.argv[1]
        if not tunnel_url.endswith('/'):
            tunnel_url += '/'
        test_urls.insert(0, tunnel_url)
        print(f"🎯 Testing VS Code tunnel: {tunnel_url}")
    
    print(f"\n📋 Testing {len(test_urls)} URLs...")
    print()
    
    successful_urls = []
    
    for url in test_urls:
        if test_api_connection(url):
            successful_urls.append(url)
        print()
        time.sleep(1)  # Small delay between requests
    
    print("=" * 50)
    print("📊 RESULTS:")
    
    if successful_urls:
        print(f"✅ {len(successful_urls)} URLs are working:")
        for i, url in enumerate(successful_urls, 1):
            api_url = urljoin(url, "api/v1/")
            print(f"   {i}. {api_url}")
        
        print(f"\n🎯 RECOMMENDED API URL: {urljoin(successful_urls[0], 'api/v1/')}")
        
        print("\n🔗 Frontend Configuration:")
        print("```javascript")
        print(f"const API_BASE_URL = '{urljoin(successful_urls[0], 'api/v1/')}';")
        print("```")
        
    else:
        print("❌ No URLs are working!")
        print("\n🔧 Troubleshooting:")
        print("1. Make sure Django server is running: python manage.py runserver")
        print("2. Check if the port is correct (default: 8000)")
        print("3. Verify VS Code tunnel is active")
        print("4. Check firewall settings")
        print("5. Try running: python manage.py get_api_url")

if __name__ == "__main__":
    main() 