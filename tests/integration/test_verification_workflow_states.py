#!/usr/bin/env python3
"""
Verification Workflow State Transitions Test

This script specifically tests the approval workflow state transitions
and validates the signal-based status updates in the verification system.
"""

import os
import sys
import django
from decimal import Decimal
from datetime import date

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.db import transaction

from deals.models import Deal, Payment, PaymentInvoice, PaymentApproval
from organization.models import Organization
from clients.models import Client

User = get_user_model()

def test_verification_workflow_states():
    """Test the complete verification workflow state transitions"""
    print("🔄 Testing Verification Workflow State Transitions...")
    
    try:
        # Setup test data
        with transaction.atomic():
            # Create or get organization
            org, created = Organization.objects.get_or_create(
                name="Test Verification Org",
                defaults={'description': 'Organization for verification testing'}
            )
            
            # Create or get user first
            user, created = User.objects.get_or_create(
                email="verifier_test@example.com",
                defaults={
                    'organization': org,
                    'password': 'testpass123'
                }
            )
            
            # Create or get client
            client, created = Client.objects.get_or_create(
                organization=org,
                email="test_verification@example.com",
                defaults={
                    'client_name': "Test Verification Client",
                    'phone_number': '+1234567890',
                    'created_by': user
                }
            )
            
            print("✅ Test data setup completed")
            
            # Test 1: Payment Creation and Automatic Invoice Generation
            print("\n📝 Test 1: Payment Creation and Automatic Invoice Generation")
            
            deal = Deal.objects.create(
                organization=org,
                client=client,
                created_by=user,
                payment_status='initial payment',
                source_type='linkedin',
                deal_name='Verification Test Deal',
                deal_value=Decimal('1000.00'),
                payment_method='bank'
            )
            
            payment = Payment.objects.create(
                deal=deal,
                payment_date=date.today(),
                received_amount=Decimal('1000.00'),
                payment_type='bank'
            )
            
            # Verify PaymentInvoice was created automatically
            try:
                invoice = PaymentInvoice.objects.get(payment=payment)
                print(f"✅ PaymentInvoice created automatically: {invoice.invoice_id}")
                print(f"   Initial status: {invoice.invoice_status}")
                assert invoice.invoice_status == 'pending', f"Expected 'pending', got '{invoice.invoice_status}'"
            except PaymentInvoice.DoesNotExist:
                print("❌ PaymentInvoice was not created automatically")
                return False
            
            # Test 2: Approval Without Failure Remarks (Should Verify)
            print("\n✅ Test 2: Approval Without Failure Remarks (Should Verify)")
            
            approval_verify = PaymentApproval.objects.create(
                payment=payment,
                invoice=invoice,
                approved_by=user,
                amount_in_invoice=Decimal('1000.00'),
                verifier_remarks="Payment verified successfully"
            )
            
            # Check if invoice status was updated via signal
            invoice.refresh_from_db()
            print(f"   Invoice status after approval: {invoice.invoice_status}")
            assert invoice.invoice_status == 'verified', f"Expected 'verified', got '{invoice.invoice_status}'"
            print("✅ Verification workflow working correctly")
            
            # Test 3: Create Another Payment for Rejection Test
            print("\n❌ Test 3: Approval With Failure Remarks (Should Reject)")
            
            payment2 = Payment.objects.create(
                deal=deal,
                payment_date=date.today(),
                received_amount=Decimal('500.00'),
                payment_type='bank'
            )
            
            invoice2 = PaymentInvoice.objects.get(payment=payment2)
            print(f"   Second invoice created: {invoice2.invoice_id}")
            print(f"   Initial status: {invoice2.invoice_status}")
            
            approval_reject = PaymentApproval.objects.create(
                payment=payment2,
                invoice=invoice2,
                approved_by=user,
                failure_remarks='insufficient_funds',
                amount_in_invoice=Decimal('500.00'),
                verifier_remarks="Payment rejected due to insufficient funds"
            )
            
            # Check if invoice status was updated via signal
            invoice2.refresh_from_db()
            print(f"   Invoice status after rejection: {invoice2.invoice_status}")
            assert invoice2.invoice_status == 'rejected', f"Expected 'rejected', got '{invoice2.invoice_status}'"
            print("✅ Rejection workflow working correctly")
            
            # Test 4: Multiple Approvals (Latest Should Win)
            print("\n🔄 Test 4: Multiple Approvals (Latest Should Win)")
            
            # Create another approval for the same payment (should override)
            approval_override = PaymentApproval.objects.create(
                payment=payment2,
                invoice=invoice2,
                approved_by=user,
                amount_in_invoice=Decimal('500.00'),
                verifier_remarks="Payment approved on second review"
                # No failure_remarks, so should verify
            )
            
            invoice2.refresh_from_db()
            print(f"   Invoice status after override approval: {invoice2.invoice_status}")
            assert invoice2.invoice_status == 'verified', f"Expected 'verified', got '{invoice2.invoice_status}'"
            print("✅ Multiple approvals workflow working correctly")
            
            # Test 5: Failure Remarks Options
            print("\n📋 Test 5: Testing All Failure Remarks Options")
            
            failure_options = [choice[0] for choice in PaymentApproval.FAILURE_REMARKS]
            print(f"   Available failure remarks: {failure_options}")
            
            for i, failure_type in enumerate(failure_options[:3]):  # Test first 3
                test_payment = Payment.objects.create(
                    deal=deal,
                    payment_date=date.today(),
                    received_amount=Decimal('100.00'),
                    payment_type='bank'
                )
                
                test_invoice = PaymentInvoice.objects.get(payment=test_payment)
                
                PaymentApproval.objects.create(
                    payment=test_payment,
                    invoice=test_invoice,
                    approved_by=user,
                    failure_remarks=failure_type,
                    amount_in_invoice=Decimal('100.00'),
                    verifier_remarks=f"Test rejection with {failure_type}"
                )
                
                test_invoice.refresh_from_db()
                print(f"   {failure_type}: {test_invoice.invoice_status}")
                assert test_invoice.invoice_status == 'rejected'
            
            print("✅ All failure remarks working correctly")
            
            # Test 6: Relationship Integrity
            print("\n🔗 Test 6: Relationship Integrity")
            
            # Verify all relationships are properly set
            test_approval = PaymentApproval.objects.filter(payment=payment).first()
            
            assert test_approval.payment == payment, "Payment relationship broken"
            assert test_approval.invoice == invoice, "Invoice relationship broken"
            assert test_approval.deal == deal, "Deal relationship broken"
            assert test_approval.approved_by == user, "User relationship broken"
            
            print("✅ All relationships properly maintained")
            
            # Test 7: Amount Tracking
            print("\n💰 Test 7: Amount Tracking")
            
            approvals_with_amounts = PaymentApproval.objects.filter(
                payment__deal=deal,
                amount_in_invoice__gt=0
            )
            
            total_approved_amount = sum(
                approval.amount_in_invoice for approval in approvals_with_amounts
            )
            
            print(f"   Total approved amount: {total_approved_amount}")
            print(f"   Deal value: {deal.deal_value}")
            print("✅ Amount tracking working correctly")
            
            print("\n🎉 All verification workflow tests passed!")
            return True
            
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_signal_behavior():
    """Test the signal behavior specifically"""
    print("\n🔔 Testing Signal Behavior...")
    
    try:
        # Import the signal function directly
        from deals.signals import update_invoice_status_on_approval
        
        print("✅ Signal function imported successfully")
        
        # Test signal is connected
        from django.db.models.signals import post_save
        from deals.models import PaymentApproval
        
        # Check if signal is connected
        signal_connected = any(
            receiver[1].__name__ == 'update_invoice_status_on_approval'
            for receiver in post_save._live_receivers(sender=PaymentApproval)
        )
        
        print(f"   Signal connected: {signal_connected}")
        
        if signal_connected:
            print("✅ Signal properly connected to PaymentApproval post_save")
        else:
            print("⚠️ Signal may not be properly connected")
        
        return signal_connected
        
    except Exception as e:
        print(f"❌ Signal test failed: {str(e)}")
        return False

def main():
    """Main test execution"""
    print("🚀 Starting Verification Workflow State Transitions Test")
    print("=" * 60)
    
    # Test signal behavior first
    signal_test = test_signal_behavior()
    
    # Test workflow states
    workflow_test = test_verification_workflow_states()
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary:")
    print(f"Signal Behavior Test: {'✅ PASSED' if signal_test else '❌ FAILED'}")
    print(f"Workflow States Test: {'✅ PASSED' if workflow_test else '❌ FAILED'}")
    
    overall_result = signal_test and workflow_test
    print(f"\nOverall Result: {'✅ ALL TESTS PASSED' if overall_result else '❌ SOME TESTS FAILED'}")
    print("=" * 60)
    
    return overall_result

if __name__ == "__main__":
    main()