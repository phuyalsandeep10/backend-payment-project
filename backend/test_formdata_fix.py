#!/usr/bin/env python
"""
Test FormData parsing fix
"""

import os
import sys
import django
from django.http import QueryDict
from django.core.files.uploadedfile import SimpleUploadedFile

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
django.setup()

def test_formdata_parsing():
    """Test the FormData parsing logic from the view"""
    print("🧪 Testing FormData parsing logic...")
    
    # Create a QueryDict to simulate FormData
    data = QueryDict(mutable=True)
    data.update({
        'client_id': '2',
        'deal_name': 'Test Deal',
        'payment_status': 'partial_payment',
        'source_type': 'instagram',
        'currency': 'USD',
        'deal_value': '10000',
        'deal_date': '2025-08-19',
        'due_date': '2025-08-23',
        'payment_method': 'bank',
        'deal_remarks': 'Test remarks',
        'payments[0][payment_date]': '2025-08-19',
        'payments[0][received_amount]': '1000',
        'payments[0][cheque_number]': '12345678900000',
        'payments[0][payment_remarks]': 'Test payment',
    })
    
    # Add a test file
    test_file = SimpleUploadedFile(
        "test_receipt.png",
        b"fake image content",
        content_type="image/png"
    )
    data['payments[0][receipt_file]'] = test_file
    
    print(f"📋 Original data keys: {list(data.keys())}")
    
    # Simulate the parsing logic from the view
    import logging
    logger = logging.getLogger(__name__)
    
    # Parse nested payment fields
    payment_data = []
    payment_indices = set()
    
    # Find payment field indices
    for key in data.keys():
        if key.startswith('payments[') and '][' in key:
            try:
                index = int(key.split('[')[1].split(']')[0])
                payment_indices.add(index)
            except (ValueError, IndexError):
                continue
    
    print(f"🔍 Found payment indices: {payment_indices}")
    
    # Group fields by payment index
    for index in payment_indices:
        payment_item = {}
        prefix = f'payments[{index}]'
        
        for key in list(data.keys()):
            if key.startswith(prefix):
                field_name = key.replace(f'{prefix}[', '').replace(']', '')
                
                if field_name:
                    value = data.get(key)
                    
                    if value is not None and value != '':
                        payment_item[field_name] = value
                    
                    # Remove the original key to avoid conflicts
                    if key in data:
                        del data[key]
        
        if payment_item:
            payment_data.append(payment_item)
            print(f"💰 Payment item {index}: {payment_item}")
    
    # Create combined data
    if payment_data:
        combined_data = {}
        
        # Copy all non-payment fields from QueryDict
        for key in data.keys():
            if not key.startswith('payments['):
                combined_data[key] = data.get(key)
        
        # Add the parsed payments
        combined_data['payments'] = payment_data
        data = combined_data
        print(f"✅ Created combined data with {len(payment_data)} payments")
        print(f"📋 Final data keys: {list(data.keys())}")
        
        # Check if file is preserved
        if payment_data and 'receipt_file' in payment_data[0]:
            file_obj = payment_data[0]['receipt_file']
            print(f"📎 File preserved: {file_obj.name} ({type(file_obj)})")
        
        return True
    else:
        print("❌ No payment data found")
        return False

if __name__ == "__main__":
    success = test_formdata_parsing()
    if success:
        print("🎯 FormData parsing test PASSED!")
    else:
        print("❌ FormData parsing test FAILED!")