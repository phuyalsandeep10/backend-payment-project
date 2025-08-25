#!/usr/bin/env python3
"""
Script to fix existing payment statuses based on their PaymentApproval records.
This updates Payment.status to match the approval status.
"""

import os
import django
import sys

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from apps.deals.models import Payment, PaymentApproval, PaymentInvoice

def fix_payment_statuses():
    """Update existing payment statuses based on their approvals."""
    print("🔄 Fixing existing payment statuses...")
    
    # Get all payments
    payments = Payment.objects.all()
    print(f"📊 Found {payments.count()} payments to check")
    
    updated_count = 0
    
    for payment in payments:
        print(f"\n🔍 Checking Payment ID: {payment.id}")
        print(f"   Current status: {payment.status}")
        
        # Method 1: Check PaymentApproval records
        latest_approval = payment.approvals.order_by('-approval_date').first()
        
        new_status = None
        
        if latest_approval:
            print(f"   Found approval: {latest_approval.id}")
            print(f"   Approval status: {getattr(latest_approval, 'approval_status', 'N/A')}")
            print(f"   Failure remarks: {latest_approval.failure_remarks}")
            
            # Use the same logic as the signal
            if (hasattr(latest_approval, 'approval_status') and latest_approval.approval_status == 'rejected') or latest_approval.failure_remarks:
                new_status = 'rejected'
            elif (hasattr(latest_approval, 'approval_status') and latest_approval.approval_status == 'approved'):
                new_status = 'verified'
            else:
                # Fallback logic
                if latest_approval.failure_remarks:
                    new_status = 'rejected'
                else:
                    new_status = 'verified'
        else:
            # Method 2: Check PaymentInvoice status
            try:
                invoice = PaymentInvoice.objects.get(payment=payment)
                print(f"   Found invoice: {invoice.id}")
                print(f"   Invoice status: {invoice.invoice_status}")
                
                if invoice.invoice_status in ['verified', 'rejected']:
                    new_status = invoice.invoice_status
                else:
                    new_status = 'pending'
            except PaymentInvoice.DoesNotExist:
                print("   No invoice found, keeping as pending")
                new_status = 'pending'
        
        if new_status and new_status != payment.status:
            old_status = payment.status
            payment.status = new_status
            payment.save()
            updated_count += 1
            print(f"   ✅ Updated: {old_status} → {new_status}")
        else:
            print(f"   ⏭️  No change needed (status: {payment.status})")
    
    print(f"\n🎉 Completed! Updated {updated_count} payments")
    
    # Show summary
    print("\n📊 Payment Status Summary:")
    for status in ['pending', 'verified', 'rejected']:
        count = Payment.objects.filter(status=status).count()
        print(f"   {status.capitalize()}: {count}")

if __name__ == '__main__':
    try:
        fix_payment_statuses()
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)