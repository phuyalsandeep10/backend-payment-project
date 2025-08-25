#!/usr/bin/env python
"""
Test FormData parsing logic without Django
"""

class MockFile:
    def __init__(self, name):
        self.name = name
    
    def __repr__(self):
        return f"MockFile({self.name})"

class MockQueryDict:
    def __init__(self):
        self._data = {}
        self._mutable = True
    
    def update(self, data):
        self._data.update(data)
    
    def keys(self):
        return self._data.keys()
    
    def get(self, key):
        return self._data.get(key)
    
    def __setitem__(self, key, value):
        self._data[key] = value
    
    def __getitem__(self, key):
        return self._data[key]
    
    def __delitem__(self, key):
        del self._data[key]
    
    def __contains__(self, key):
        return key in self._data

def test_formdata_parsing():
    """Test the FormData parsing logic"""
    print("🧪 Testing FormData parsing logic...")
    
    # Create mock data
    data = MockQueryDict()
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
        'payments[0][receipt_file]': MockFile('test_receipt.png'),
    })
    
    print(f"📋 Original data keys: {list(data.keys())}")
    
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
        
        keys_to_delete = []
        for key in data.keys():
            if key.startswith(prefix):
                field_name = key.replace(f'{prefix}[', '').replace(']', '')
                
                if field_name:
                    value = data.get(key)
                    
                    if value is not None and value != '':
                        payment_item[field_name] = value
                    
                    keys_to_delete.append(key)
        
        # Delete keys after iteration
        for key in keys_to_delete:
            del data[key]
        
        if payment_item:
            payment_data.append(payment_item)
            print(f"💰 Payment item {index}: {payment_item}")
    
    # Create combined data
    if payment_data:
        combined_data = {}
        
        # Copy all non-payment fields
        for key in data.keys():
            if not key.startswith('payments['):
                combined_data[key] = data.get(key)
        
        # Add the parsed payments
        combined_data['payments'] = payment_data
        
        print(f"✅ Created combined data with {len(payment_data)} payments")
        print(f"📋 Final data keys: {list(combined_data.keys())}")
        
        # Check if file is preserved
        if payment_data and 'receipt_file' in payment_data[0]:
            file_obj = payment_data[0]['receipt_file']
            print(f"📎 File preserved: {file_obj.name} ({type(file_obj)})")
        
        return True, combined_data
    else:
        print("❌ No payment data found")
        return False, None

if __name__ == "__main__":
    success, data = test_formdata_parsing()
    if success:
        print("🎯 FormData parsing test PASSED!")
        print(f"📄 Final data structure: {data}")
    else:
        print("❌ FormData parsing test FAILED!")