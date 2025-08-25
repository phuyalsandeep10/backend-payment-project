#!/usr/bin/env python
"""
Debug script to test FormData parsing
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from apps.deals.serializers.deal_serializers import DealSerializer

def test_formdata_parsing():
    """Test FormData parsing with sample data"""
    
    print("🧪 Testing FormData parsing...")
    
    # Simulate the FormData structure from your request
    sample_formdata = {
        'client_id': '2',
        'deal_name': 'Mobile development',
        'payment_status': 'partial_payment',
        'source_type': 'instagram',
        'currency': 'USD',
        'deal_value': '10000',
        'deal_date': '2025-08-19',
        'due_date': '2025-08-23',
        'payment_method': 'bank',
        'deal_remarks': 'erre',
        'payments[0][payment_date]': '2025-08-19',
        'payments[0][received_amount]': '1000',
        'payments[0][cheque_number]': '12345678900000',
        'payments[0][payment_remarks]': 'rere',
        # Note: receipt_file would be a file object in real request
    }
    
    print(f"📋 Sample FormData keys: {list(sample_formdata.keys())}")
    
    # Test the serializer
    serializer = DealSerializer(data=sample_formdata)
    
    print(f"🔍 Serializer initial_data after init: {serializer.initial_data}")
    
    # Check if payments were parsed
    if 'payments' in serializer.initial_data:
        print(f"✅ Payments found: {serializer.initial_data['payments']}")
    else:
        print("❌ No payments found in initial_data")
    
    # Test validation
    is_valid = serializer.is_valid()
    print(f"🎯 Serializer is_valid: {is_valid}")
    
    if not is_valid:
        print(f"❌ Validation errors: {serializer.errors}")
    else:
        print("✅ Validation passed!")
    
    return is_valid

def test_multipart_formdata():
    """Test with Django's QueryDict to simulate multipart form data"""
    
    print("\n🧪 Testing with QueryDict (multipart simulation)...")
    
    from django.http import QueryDict
    
    # Create a QueryDict to simulate multipart form data
    formdata = QueryDict(mutable=True)
    formdata.update({
        'client_id': '2',
        'deal_name': 'Mobile development',
        'payment_status': 'partial_payment',
        'source_type': 'instagram',
        'currency': 'USD',
        'deal_value': '10000',
        'deal_date': '2025-08-19',
        'due_date': '2025-08-23',
        'payment_method': 'bank',
        'deal_remarks': 'erre',
        'payments[0][payment_date]': '2025-08-19',
        'payments[0][received_amount]': '1000',
        'payments[0][cheque_number]': '12345678900000',
        'payments[0][payment_remarks]': 'rere',
    })
    
    print(f"📋 QueryDict keys: {list(formdata.keys())}")
    
    # Test the view-level parsing (simulate what the view does)
    parsed_data = formdata.copy()
    parsed_data._mutable = True
    
    # Parse nested payment fields (same logic as in view)
    payment_data = []
    payment_indices = set()
    
    for key in list(parsed_data.keys()):
        if key.startswith('payments[') and '][' in key:
            try:
                index = int(key.split('[')[1].split(']')[0])
                payment_indices.add(index)
            except (ValueError, IndexError):
                continue
    
    for index in payment_indices:
        payment_item = {}
        prefix = f'payments[{index}]'
        
        for key in list(parsed_data.keys()):
            if key.startswith(prefix):
                field_name = key.replace(f'{prefix}[', '').replace(']', '')
                
                if field_name:
                    value = parsed_data.get(key)
                    if value is not None and value != '':
                        payment_item[field_name] = value
                    
                    # Remove the original key
                    del parsed_data[key]
        
        if payment_item:
            payment_data.append(payment_item)
    
    if payment_data:
        parsed_data.setlist('payments', payment_data)
    
    print(f"🔧 Parsed data keys: {list(parsed_data.keys())}")
    print(f"🔧 Parsed payments: {parsed_data.getlist('payments') if hasattr(parsed_data, 'getlist') else parsed_data.get('payments')}")
    
    # Test the serializer with parsed data
    serializer = DealSerializer(data=parsed_data)
    
    # Test validation
    is_valid = serializer.is_valid()
    print(f"🎯 Serializer is_valid: {is_valid}")
    
    if not is_valid:
        print(f"❌ Validation errors: {serializer.errors}")
    else:
        print("✅ Validation passed!")
    
    return is_valid

if __name__ == "__main__":
    success1 = test_formdata_parsing()
    success2 = test_multipart_formdata()
    sys.exit(0 if (success1 and success2) else 1)