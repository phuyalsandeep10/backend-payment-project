#!/usr/bin/env python3
"""
Test script to simulate the commission API endpoint
"""
import os
import sys
import django

# Setup Django environment
sys.path.append('/Users/shishirkafle/Desktop/Frontend/Backend_PRS/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from apps.authentication.models import User
from apps.organization.models import Organization
from apps.deals.models import Deal
from apps.commission.views import OrgAdminCommissionView
from django.test import RequestFactory
from django.contrib.auth.models import AnonymousUser
from decimal import Decimal

def test_commission_api():
    """Test the actual commission API endpoint"""
    print("🔍 Testing Commission API Endpoint")
    print("=" * 50)
    
    # Find an organization with users
    brahmabytelab = Organization.objects.filter(name="Brahmabytelab").first()
    if not brahmabytelab:
        print("❌ Brahmabytelab organization not found")
        return
        
    print(f"🏢 Using Organization: {brahmabytelab.name}")
    
    # Find an org admin or create a mock user
    org_admin = User.objects.filter(
        organization=brahmabytelab,
        role__name="Organization Admin"
    ).first()
    
    if not org_admin:
        print("❌ No Organization Admin found")
        return
    
    print(f"👤 Using Admin User: {org_admin.email}")
    
    # Create a mock request
    factory = RequestFactory()
    request = factory.get('/api/commission/commissions/org-admin/')
    request.user = org_admin
    
    # Create the view and call the get method
    view = OrgAdminCommissionView()
    view.request = request
    
    try:
        response = view.get(request)
        print(f"📊 API Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.data
            print(f"📈 Commission Data Length: {len(data) if isinstance(data, list) else 'Not a list'}")
            
            for i, item in enumerate(data if isinstance(data, list) else []):
                print(f"   {i+1}. {item.get('fullName', 'Unknown')} - Total Sales: {item.get('totalSales', 0)} - Commission ID: {item.get('id', 'None')}")
        else:
            print(f"❌ API Error: {response.data if hasattr(response, 'data') else 'No data'}")
            
    except Exception as e:
        print(f"❌ Exception occurred: {str(e)}")
        import traceback
        traceback.print_exc()

def create_test_deal():
    """Create a test deal for one of the salespeople"""
    print("\n🎯 Creating Test Deal")
    print("-" * 30)
    
    # Find a salesperson
    salesperson = User.objects.filter(
        organization__name="Brahmabytelab",
        role__name="Salesperson"
    ).first()
    
    if not salesperson:
        print("❌ No salesperson found")
        return
        
    print(f"👨‍💼 Creating deal for: {salesperson.first_name} {salesperson.last_name}")
    
    # First create or find a client
    from apps.clients.models import Client
    client, created = Client.objects.get_or_create(
        email="testclient@test.com",
        defaults={
            'client_name': 'Test Commission Client',
            'phone_number': '+977-9876543210',
            'status': 'active',
            'organization': salesperson.organization,
            'created_by': salesperson
        }
    )
    
    if created:
        print(f"✅ Created test client: {client.client_name}")
    else:
        print(f"🔍 Using existing client: {client.client_name}")
    
    # Create a test deal
    deal = Deal.objects.create(
        deal_id=f"TEST_{salesperson.id}",
        organization=salesperson.organization,
        client=client,
        created_by=salesperson,
        deal_name="Test Commission Deal",
        deal_value=100000,  # 100,000 value deal
        currency="NPR",
        deal_date="2024-01-15",
        payment_status="full_payment",
        verification_status="verified",  # This is important for commission calculation
        client_status="loyal",
        source_type="referral",
        payment_method="bank",
        deal_remarks="Test deal for commission calculation"
    )
    
    print(f"✅ Created deal: {deal.deal_id} with value {deal.deal_value}")
    return deal

if __name__ == '__main__':
    test_commission_api()
    print()
    create_test_deal()
    print()
    print("🔄 Re-testing API after creating deal:")
    test_commission_api()