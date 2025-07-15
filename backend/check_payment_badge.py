#!/usr/bin/env python
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from deals.models import Deal
from deals.serializers import PaymentSerializer

# Get the latest deal
deal = Deal.objects.latest('created_at')
print(f"Latest deal: {deal.deal_id}")
print(f"Deal value: {deal.deal_value}")
print(f"Payment status: {deal.payment_status}")

# Get all payments
payments = deal.payments.all()
print(f"Payments count: {payments.count()}")

for i, payment in enumerate(payments):
    print(f"\nPayment {i+1}:")
    print(f"  Amount: {payment.received_amount}")
    print(f"  Type: {payment.payment_type}")
    print(f"  Date: {payment.payment_date}")
    print(f"  Cheque: {payment.cheque_number}")
    print(f"  Remarks: {payment.payment_remarks}")
    
    # Check if payment has status field
    if hasattr(payment, 'status'):
        print(f"  Status: {payment.status}")
    else:
        print(f"  Status: No status field")
    
    # Check if payment has verified_amount field
    if hasattr(payment, 'verified_amount'):
        print(f"  Verified amount: {payment.verified_amount}")
    else:
        print(f"  Verified amount: No verified_amount field")

# Test the PaymentSerializer
print(f"\n--- Testing PaymentSerializer ---")
for payment in payments:
    serializer = PaymentSerializer(payment)
    data = serializer.data
    print(f"Payment {payment.id} serialized data:")
    print(f"  Status: {data.get('status')}")
    print(f"  Verified amount: {data.get('verified_amount')}")
    print(f"  Received amount: {data.get('received_amount')}") 