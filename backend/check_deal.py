#!/usr/bin/env python
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from deals.models import Deal
from deals.serializers import PaymentSerializer

# Check the specific deal
deal = Deal.objects.get(deal_id='DLID0004')
print(f"Deal: {deal.deal_id}")
print(f"Deal Value: {deal.deal_value}")
print(f"Payment Status: {deal.payment_status}")
print(f"Verification Status: {deal.verification_status}")

payments = deal.payments.all()
print(f"Total Payments: {payments.count()}")

total_paid = 0
for payment in payments:
    print(f"Payment: {payment.received_amount}, Date: {payment.payment_date}")
    total_paid += float(payment.received_amount)

print(f"Total Paid: {total_paid}")
print(f"Remaining: {float(deal.deal_value) - total_paid}")
print(f"Should be full_payment: {total_paid >= float(deal.deal_value)}")

# Check payment serializer status
for payment in payments:
    serializer = PaymentSerializer(payment)
    status = serializer.get_status(payment)
    verified_amount = serializer.get_verified_amount(payment)
    print(f"Payment {payment.id}: Status={status}, Verified Amount={verified_amount}, Received Amount={payment.received_amount}")

# Check if there are any payment approvals
for payment in payments:
    approvals = payment.approvals.all()
    print(f"Payment {payment.id} approvals: {approvals.count()}")
    for approval in approvals:
        print(f"  Approval: {approval.approval_date}, Amount: {approval.amount_in_invoice}, Failure: {approval.failure_remarks}") 