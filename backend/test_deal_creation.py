#!/usr/bin/env python
"""
Test script to simulate deal creation with FormData parsing
"""

import os
import sys
import django
from django.conf import settings

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
django.setup()

from django.test import RequestFactory
from django.contrib.auth import get_user_model
from django.http import QueryDict
from django.core.files.uploadedfile import SimpleUploadedFile
from apps.deals.views import DealViewSet
from apps.clients.models import Client
from apps.authentication.models import Organization
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_deal_creation():
    """Test deal creation with FormData parsing"""
    print("🧪 Testing Deal Creation with FormData...")
    
    try:
        # Get or create test organization
        org, _ = Organization.objects.get_or_create(
            name="Test Org",
            defaults={'email': 'test@example.com'}
        )
        
        # Get or create test user
        User = get_user_model()
        user, _ = User.objects.get_or_create(
            email='test@example.com',
            defaults={
                'first_name': 'Test',
                'last_name': 'User',
                'organization': org
            }
        )
        
        # Get or create test client
        client, _ = Client.objects.get_or_create(
            client_name="Test Client",
            defaults={
                'organization': org,
                'email': 'client@example.com'
            }
        )
        
        # Create a QueryDict to simulate FormData
        data = QueryDict(mutable=True)
        data.update({
            'client_id': str(client.id),
            'deal_name': 'Test Deal with Payments',
            'payment_status': 'full_payment',
            'source_type': 'linkedin',
            'currency': 'USD',
            'deal_value': '5000.00',
            'deal_date': '2025-08-19',
            'due_date': '2025-08-23',
            'payment_method': 'bank',
            'deal_remarks': 'Test deal with payment data',
            'payments[0][payment_date]': '2025-08-19',
            'payments[0][received_amount]': '5000.00',
            'payments[0][cheque_number]': 'TEST123456',
            'payments[0][payment_remarks]': 'Full payment received',
        })
        
        # Add a test file
        test_file = SimpleUploadedFile(
            "test_receipt.txt",
            b"Test receipt content",
            content_type="text/plain"
        )
        data['payments[0][receipt_file]'] = test_file
        
        # Create request
        factory = RequestFactory()
        request = factory.post('/api/deals/deals/', data=data, content_type='multipart/form-data')
        request.user = user
        
        # Create viewset instance
        viewset = DealViewSet()
        viewset.request = request
        viewset.format_kwarg = None
        
        print("📋 Request data keys:", list(request.POST.keys()))
        print("📋 Request files:", list(request.FILES.keys()))
        
        # Test the create method
        response = viewset.create(request)
        
        print(f"🎯 Response status: {response.status_code}")
        if response.status_code == 201:
            print("✅ Deal created successfully!")
            print(f"📄 Response data: {response.data}")
        else:
            print("❌ Deal creation failed!")
            print(f"📄 Response data: {response.data}")
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_deal_creation()