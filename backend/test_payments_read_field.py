#!/usr/bin/env python3
"""
Test script to verify that payments_read field is included in API responses
for org-admin and verifier users.
"""

import requests
import json
from datetime import datetime

# API base URL
BASE_URL = "http://localhost:8000/api"

def test_api_response(endpoint, headers=None):
    """Test an API endpoint and return the response"""
    try:
        response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
        print(f"\n🔍 Testing: {endpoint}")
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Response keys: {list(data.keys()) if isinstance(data, dict) else 'Not a dict'}")
            
            # Check if it's a paginated response
            if isinstance(data, dict) and 'results' in data:
                print(f"Number of deals: {len(data['results'])}")
                if data['results']:
                    first_deal = data['results'][0]
                    print(f"First deal keys: {list(first_deal.keys())}")
                    print(f"Has payments_read: {'payments_read' in first_deal}")
                    if 'payments_read' in first_deal:
                        print(f"payments_read length: {len(first_deal['payments_read'])}")
                        if first_deal['payments_read']:
                            print(f"First payment keys: {list(first_deal['payments_read'][0].keys())}")
            elif isinstance(data, list) and data:
                print(f"Number of deals: {len(data)}")
                first_deal = data[0]
                print(f"First deal keys: {list(first_deal.keys())}")
                print(f"Has payments_read: {'payments_read' in first_deal}")
                if 'payments_read' in first_deal:
                    print(f"payments_read length: {len(first_deal['payments_read'])}")
                    if first_deal['payments_read']:
                        print(f"First payment keys: {list(first_deal['payments_read'][0].keys())}")
        else:
            print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"Error testing {endpoint}: {e}")

def main():
    print("🧪 Testing payments_read field in API responses")
    print("=" * 50)
    
    # Test the main deals endpoint (used by org-admin)
    test_api_response("/deals/deals/")
    
    # Test the verifier deals endpoint
    test_api_response("/verifier/deals/")
    
    print("\n✅ Test completed!")

if __name__ == "__main__":
    main() 