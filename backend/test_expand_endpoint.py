#!/usr/bin/env python
import os
import sys
import django

# Add the project directory to the Python path
sys.path.append('/Users/shishirkafle/Desktop/Frontend/Backend_PRS/backend')

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from deals.models import Deal
from deals.serializers import DealExpandedViewSerializer

# Get a deal that has payments
deal = Deal.objects.filter(payments__isnull=False).first()

if deal:
    print(f"Testing expand endpoint for deal: {deal.deal_id}")
    print(f"Deal has {deal.payments.count()} payments")
    
    # Test the serializer
    serializer = DealExpandedViewSerializer(deal)
    data = serializer.data
    
    print(f"Serialized data keys: {list(data.keys())}")
    print(f"Payment history: {data.get('payment_history', [])}")
    print(f"Payment history length: {len(data.get('payment_history', []))}")
    
    if data.get('payment_history'):
        print("First payment in history:")
        print(data['payment_history'][0])
else:
    print("No deals with payments found") 