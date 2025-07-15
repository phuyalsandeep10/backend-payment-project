#!/usr/bin/env python
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from deals.models import Deal, Payment

# Find the test deal (get the most recent one if multiple exist)
deals = Deal.objects.filter(deal_id='DLID0004').order_by('-created_at')
if deals.exists():
    deal = deals.first()
    print(f"Found deal: {deal.deal_id} (created: {deal.created_at})")
else:
    print("Deal DLID0004 not found")
    exit()

# Get all payments for this deal
payments = deal.payments.all()
print(f"Total payments: {payments.count()}")

for payment in payments:
    print(f"Payment: {payment.received_amount}, Date: {payment.payment_date}, Remarks: {payment.payment_remarks}")

# Find the auto-created payment (the one with full deal value and "Initial payment" remarks)
auto_payment = None
for payment in payments:
    if (float(payment.received_amount) == float(deal.deal_value) and 
        "Initial payment" in payment.payment_remarks):
        auto_payment = payment
        break

if auto_payment:
    print(f"Found auto-created payment: {auto_payment.received_amount}")
    print("Deleting auto-created payment...")
    auto_payment.delete()
    print("Auto-created payment deleted!")
else:
    print("No auto-created payment found")

# Check remaining payments
remaining_payments = deal.payments.all()
print(f"Remaining payments: {remaining_payments.count()}")
for payment in remaining_payments:
    print(f"Remaining payment: {payment.received_amount}, Date: {payment.payment_date}") 