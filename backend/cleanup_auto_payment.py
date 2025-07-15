#!/usr/bin/env python
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from deals.models import Deal, Payment

# Get the latest deal
deal = Deal.objects.latest('created_at')
print(f"Latest deal: {deal.deal_id}")

# Get all payments for this deal
payments = deal.payments.all()
print(f"Total payments: {payments.count()}")

# Find and remove the auto-created payment (the one with full deal value and "Initial payment" remarks)
auto_payment = None
for payment in payments:
    print(f"Payment: {payment.received_amount}, Remarks: {payment.payment_remarks}")
    if (float(payment.received_amount) == float(deal.deal_value) and 
        "Initial payment" in payment.payment_remarks):
        auto_payment = payment
        break

if auto_payment:
    print(f"Removing auto-created payment: {auto_payment.received_amount}")
    auto_payment.delete()
    print("Auto-created payment removed successfully!")
else:
    print("No auto-created payment found")

# Verify the remaining payment
remaining_payments = deal.payments.all()
print(f"Remaining payments: {remaining_payments.count()}")
for payment in remaining_payments:
    print(f"Remaining payment: {payment.received_amount}, Remarks: {payment.payment_remarks}") 