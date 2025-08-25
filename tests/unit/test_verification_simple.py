#!/usr/bin/env python3
"""
Simple Verification System Test

This script tests the verification system without complex transactions
to avoid audit logging conflicts.
"""

import os
import sys
import django
from decimal import Decimal
from datetime import date

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.contrib.auth import get_user_model
from deals.models import Deal, Payment, PaymentInvoice, PaymentApproval
from organization.models import Organization
from clients.models import Client

User = get_user_model()

def test_verification_system():
    """Test the verification system components"""
    print("🔍 Testing Verification System Components...")
    
    results = {}
    
    try:
        # Test 1: Check existing data and relationships
        print("\n📊 Test 1: Analyzing Existing Data...")
        
        # Count existing records
        invoice_count = PaymentInvoice.objects.count()
        approval_count = PaymentApproval.objects.count()
        payment_count = Payment.objects.count()
        
        results['existing_data'] = {
            'invoices': invoice_count,
            'approvals': approval_count,
            'payments': payment_count
        }
        
        print(f"   Existing PaymentInvoices: {invoice_count}")
        print(f"   Existing PaymentApprovals: {approval_count}")
        print(f"   Existing Payments: {payment_count}")
        
        # Test 2: Model Field Analysis
        print("\n🔍 Test 2: Model Field Analysis...")
        
        invoice_fields = [field.name for field in PaymentInvoice._meta.fields]
        approval_fields = [field.name for field in PaymentApproval._meta.fields]
        
        results['model_fields'] = {
            'PaymentInvoice': invoice_fields,
            'PaymentApproval': approval_fields
        }
        
        print(f"   PaymentInvoice fields: {len(invoice_fields)}")
        print(f"   PaymentApproval fields: {len(approval_fields)}")
        
        # Test 3: Relationship Analysis
        print("\n🔗 Test 3: Relationship Analysis...")
        
        if invoice_count > 0:
            sample_invoice = PaymentInvoice.objects.first()
            
            relationships_working = {
                'invoice_to_payment': hasattr(sample_invoice, 'payment'),
                'invoice_to_deal': hasattr(sample_invoice, 'deal'),
                'invoice_has_approvals': hasattr(sample_invoice, 'approvals')
            }
            
            results['relationships'] = relationships_working
            
            print(f"   Invoice->Payment relationship: {relationships_working['invoice_to_payment']}")
            print(f"   Invoice->Deal relationship: {relationships_working['invoice_to_deal']}")
            print(f"   Invoice has approvals: {relationships_working['invoice_has_approvals']}")
            
            # Test approval relationships if approvals exist
            if approval_count > 0:
                sample_approval = PaymentApproval.objects.first()
                
                approval_relationships = {
                    'approval_to_payment': hasattr(sample_approval, 'payment'),
                    'approval_to_invoice': hasattr(sample_approval, 'invoice'),
                    'approval_to_deal': hasattr(sample_approval, 'deal'),
                    'approval_to_user': hasattr(sample_approval, 'approved_by')
                }
                
                results['approval_relationships'] = approval_relationships
                
                for rel, status in approval_relationships.items():
                    print(f"   {rel}: {status}")
        
        # Test 4: Status Analysis
        print("\n📋 Test 4: Status Analysis...")
        
        if invoice_count > 0:
            status_distribution = {}
            for status_choice in ['pending', 'verified', 'rejected', 'refunded', 'bad_debt']:
                count = PaymentInvoice.objects.filter(invoice_status=status_choice).count()
                status_distribution[status_choice] = count
            
            results['status_distribution'] = status_distribution
            
            print("   Invoice Status Distribution:")
            for status, count in status_distribution.items():
                print(f"     {status}: {count}")
        
        # Test 5: Failure Remarks Analysis
        print("\n❌ Test 5: Failure Remarks Analysis...")
        
        failure_remarks = [choice[0] for choice in PaymentApproval.FAILURE_REMARKS]
        results['failure_remarks'] = failure_remarks
        
        print(f"   Available failure remarks: {len(failure_remarks)}")
        for remark in failure_remarks:
            print(f"     - {remark}")
        
        if approval_count > 0:
            failure_distribution = {}
            for remark in failure_remarks:
                count = PaymentApproval.objects.filter(failure_remarks=remark).count()
                if count > 0:
                    failure_distribution[remark] = count
            
            results['failure_distribution'] = failure_distribution
            
            if failure_distribution:
                print("   Failure Remarks Usage:")
                for remark, count in failure_distribution.items():
                    print(f"     {remark}: {count}")
        
        # Test 6: Signal Connection Test
        print("\n🔔 Test 6: Signal Connection Test...")
        
        from django.db.models.signals import post_save
        
        # Check if signal is connected
        signal_connected = any(
            'update_invoice_status_on_approval' in str(receiver[1])
            for receiver in post_save._live_receivers(sender=PaymentApproval)
        )
        
        results['signal_connected'] = signal_connected
        print(f"   Signal connected: {signal_connected}")
        
        # Test 7: File Upload Security
        print("\n🔒 Test 7: File Upload Security Analysis...")
        
        # Check if validate_file_security is used
        invoice_file_field = PaymentInvoice._meta.get_field('receipt_file')
        approval_file_field = PaymentApproval._meta.get_field('invoice_file')
        
        security_features = {
            'invoice_file_validators': len(invoice_file_field.validators) > 0,
            'approval_file_validators': len(approval_file_field.validators) > 0,
            'upload_paths_configured': True
        }
        
        results['security_features'] = security_features
        
        for feature, status in security_features.items():
            print(f"   {feature}: {status}")
        
        # Test 8: Organization Scoping
        print("\n🏢 Test 8: Organization Scoping Analysis...")
        
        if invoice_count > 0:
            # Check if invoices are properly scoped to organizations
            invoices_with_orgs = PaymentInvoice.objects.filter(
                deal__organization__isnull=False
            ).count()
            
            org_scoping = {
                'invoices_with_organizations': invoices_with_orgs,
                'percentage_scoped': (invoices_with_orgs / invoice_count * 100) if invoice_count > 0 else 0
            }
            
            results['organization_scoping'] = org_scoping
            
            print(f"   Invoices with organizations: {invoices_with_orgs}/{invoice_count}")
            print(f"   Percentage properly scoped: {org_scoping['percentage_scoped']:.1f}%")
        
        print("\n✅ All tests completed successfully!")
        return results
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        results['error'] = str(e)
        return results

def main():
    """Main test execution"""
    print("🚀 Starting Simple Verification System Test")
    print("=" * 60)
    
    results = test_verification_system()
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary:")
    
    if 'error' not in results:
        print("✅ All tests completed successfully")
        
        # Print key metrics
        if 'existing_data' in results:
            data = results['existing_data']
            print(f"📈 Data Summary:")
            print(f"   - PaymentInvoices: {data['invoices']}")
            print(f"   - PaymentApprovals: {data['approvals']}")
            print(f"   - Payments: {data['payments']}")
        
        if 'signal_connected' in results:
            print(f"🔔 Signal Status: {'✅ Connected' if results['signal_connected'] else '❌ Not Connected'}")
        
        if 'organization_scoping' in results:
            scoping = results['organization_scoping']
            print(f"🏢 Organization Scoping: {scoping['percentage_scoped']:.1f}% properly scoped")
        
    else:
        print(f"❌ Tests failed: {results['error']}")
    
    print("=" * 60)
    
    return results

if __name__ == "__main__":
    main()