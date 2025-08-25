#!/usr/bin/env python3
"""
Simplified Payment Processing System Analysis
Focus on analyzing existing payment data and system components.

Task 3: Payment Processing System Analysis
- Validate payment model financial calculations and precision
- Test payment creation, validation, and approval workflows  
- Analyze transaction ID generation and uniqueness
- Examine file upload security for payment receipts
"""

import os
import sys
import django
import tempfile
import io
from decimal import Decimal
from datetime import datetime
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from deals.models import Deal, Payment, PaymentInvoice, PaymentApproval
from deals.financial_optimizer import FinancialFieldOptimizer
from core_config.file_security import validate_file_security_enhanced

class PaymentProcessingAnalysis:
    """Simplified analysis of payment processing system"""
    
    def __init__(self):
        self.results = {
            'financial_calculations': {},
            'transaction_analysis': {},
            'file_security': {},
            'system_validation': {},
            'summary': {}
        }
    
    def analyze_financial_calculations(self):
        """Analyze payment model financial calculations and precision"""
        print("\n=== ANALYZING FINANCIAL CALCULATIONS ===")
        
        # Test 1: Decimal precision validation
        print("1. Testing decimal precision validation...")
        
        test_cases = [
            {'value': Decimal('1000.00'), 'expected': True, 'description': 'Valid currency amount'},
            {'value': Decimal('1000.001'), 'expected': False, 'description': 'Too many decimal places'},
            {'value': Decimal('999999999.99'), 'expected': True, 'description': 'Maximum allowed value'},
            {'value': Decimal('1000000000.00'), 'expected': False, 'description': 'Exceeds maximum'},
            {'value': Decimal('0.01'), 'expected': True, 'description': 'Minimum valid amount'},
            {'value': Decimal('0.00'), 'expected': False, 'description': 'Zero amount'},
            {'value': Decimal('-100.00'), 'expected': False, 'description': 'Negative amount'},
        ]
        
        precision_results = []
        for case in test_cases:
            try:
                validated = FinancialFieldOptimizer.validate_payment_amount(case['value'])
                result = True
                error = None
            except ValidationError as e:
                result = False
                error = str(e)
            
            precision_results.append({
                'value': str(case['value']),
                'expected': case['expected'],
                'actual': result,
                'passed': result == case['expected'],
                'description': case['description'],
                'error': error
            })
        
        self.results['financial_calculations']['precision_tests'] = precision_results
        
        # Test 2: Payment consistency validation
        print("2. Testing payment consistency validation...")
        
        deal_value = Decimal('5000.00')
        payment_scenarios = [
            {
                'payments': [{'amount': Decimal('2000.00')}, {'amount': Decimal('3000.00')}],
                'description': 'Exact payment match',
                'expected_fully_paid': True,
                'expected_overpaid': False
            },
            {
                'payments': [{'amount': Decimal('2000.00')}, {'amount': Decimal('2000.00')}],
                'description': 'Underpayment',
                'expected_fully_paid': False,
                'expected_overpaid': False
            },
            {
                'payments': [{'amount': Decimal('3000.00')}, {'amount': Decimal('3000.00')}],
                'description': 'Overpayment',
                'expected_fully_paid': True,
                'expected_overpaid': True
            }
        ]
        
        consistency_results = []
        for scenario in payment_scenarios:
            analysis = FinancialFieldOptimizer.validate_payment_consistency(
                deal_value, scenario['payments']
            )
            
            consistency_results.append({
                'description': scenario['description'],
                'payments': [str(p['amount']) for p in scenario['payments']],
                'total_payments': str(analysis['total_payments']),
                'remaining_balance': str(analysis['remaining_balance']),
                'is_fully_paid': analysis['is_fully_paid'],
                'is_overpaid': analysis['is_overpaid'],
                'expected_fully_paid': scenario['expected_fully_paid'],
                'expected_overpaid': scenario['expected_overpaid'],
                'fully_paid_match': analysis['is_fully_paid'] == scenario['expected_fully_paid'],
                'overpaid_match': analysis['is_overpaid'] == scenario['expected_overpaid']
            })
        
        self.results['financial_calculations']['consistency_tests'] = consistency_results
        
        # Test 3: Commission calculations
        print("3. Testing commission calculations...")
        
        commission_tests = [
            {'sales': Decimal('10000.00'), 'rate': Decimal('5.00'), 'expected': Decimal('500.00')},
            {'sales': Decimal('2500.50'), 'rate': Decimal('7.25'), 'expected': Decimal('181.29')},
            {'sales': Decimal('100.00'), 'rate': Decimal('0.50'), 'expected': Decimal('0.50')},
        ]
        
        commission_results = []
        for test in commission_tests:
            calculated = FinancialFieldOptimizer.calculate_commission_amount(
                test['sales'], test['rate']
            )
            
            commission_results.append({
                'sales_amount': str(test['sales']),
                'commission_rate': str(test['rate']),
                'expected': str(test['expected']),
                'calculated': str(calculated),
                'accurate': calculated == test['expected'],
                'difference': str(abs(calculated - test['expected']))
            })
        
        self.results['financial_calculations']['commission_tests'] = commission_results
        
        print("✓ Financial calculations analysis complete")
    
    def analyze_existing_transactions(self):
        """Analyze existing transaction IDs and payment data"""
        print("\n=== ANALYZING EXISTING TRANSACTIONS ===")
        
        # Get existing payments
        payments = Payment.objects.all()[:50]  # Limit to 50 for analysis
        
        transaction_analysis = {
            'total_payments': payments.count(),
            'transaction_id_patterns': {},
            'amount_distribution': {},
            'validation_issues': []
        }
        
        # Analyze transaction ID patterns
        print("1. Analyzing transaction ID patterns...")
        
        txn_id_analysis = []
        for payment in payments:
            if payment.transaction_id:
                pattern_valid = payment.transaction_id.startswith('TXN-')
                numeric_part = payment.transaction_id.split('-')[1] if '-' in payment.transaction_id else ''
                is_numeric = numeric_part.isdigit()
                is_padded = len(numeric_part) == 4
                
                txn_id_analysis.append({
                    'transaction_id': payment.transaction_id,
                    'pattern_valid': pattern_valid,
                    'numeric_part': numeric_part,
                    'is_numeric': is_numeric,
                    'is_padded': is_padded,
                    'overall_valid': pattern_valid and is_numeric and is_padded
                })
        
        # Check for duplicates
        txn_ids = [p.transaction_id for p in payments if p.transaction_id]
        unique_ids = set(txn_ids)
        has_duplicates = len(txn_ids) != len(unique_ids)
        
        transaction_analysis['transaction_ids'] = {
            'total_with_ids': len(txn_ids),
            'unique_count': len(unique_ids),
            'has_duplicates': has_duplicates,
            'pattern_analysis': txn_id_analysis
        }
        
        # Analyze payment amounts
        print("2. Analyzing payment amounts...")
        
        amount_analysis = []
        for payment in payments:
            try:
                # Validate amount using financial optimizer
                validated_amount = FinancialFieldOptimizer.validate_payment_amount(payment.received_amount)
                amount_valid = True
                validation_error = None
            except ValidationError as e:
                amount_valid = False
                validation_error = str(e)
            
            amount_analysis.append({
                'payment_id': payment.id,
                'amount': str(payment.received_amount),
                'amount_valid': amount_valid,
                'validation_error': validation_error
            })
        
        transaction_analysis['amount_validation'] = amount_analysis
        
        self.results['transaction_analysis'] = transaction_analysis
        
        print("✓ Transaction analysis complete")
    
    def analyze_file_upload_security(self):
        """Examine file upload security for payment receipts"""
        print("\n=== ANALYZING FILE UPLOAD SECURITY ===")
        
        # Test 1: Valid file upload
        print("1. Testing valid file uploads...")
        
        valid_file_tests = []
        
        # Test valid image file
        try:
            # Create a simple test image
            from PIL import Image
            img = Image.new('RGB', (100, 100), color='red')
            img_buffer = io.BytesIO()
            img.save(img_buffer, format='JPEG')
            img_buffer.seek(0)
            
            valid_image = SimpleUploadedFile(
                "test_receipt.jpg",
                img_buffer.getvalue(),
                content_type="image/jpeg"
            )
            
            # Test file validation
            validate_file_security_enhanced(valid_image)
            
            valid_file_tests.append({
                'file_type': 'JPEG image',
                'filename': 'test_receipt.jpg',
                'size': len(img_buffer.getvalue()),
                'validation_passed': True,
                'error': None
            })
            
        except Exception as e:
            valid_file_tests.append({
                'file_type': 'JPEG image',
                'validation_passed': False,
                'error': str(e)
            })
        
        # Test valid PDF file
        try:
            pdf_content = b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n%%EOF'
            valid_pdf = SimpleUploadedFile(
                "test_receipt.pdf",
                pdf_content,
                content_type="application/pdf"
            )
            
            validate_file_security_enhanced(valid_pdf)
            
            valid_file_tests.append({
                'file_type': 'PDF document',
                'filename': 'test_receipt.pdf',
                'size': len(pdf_content),
                'validation_passed': True,
                'error': None
            })
            
        except Exception as e:
            valid_file_tests.append({
                'file_type': 'PDF document',
                'validation_passed': False,
                'error': str(e)
            })
        
        self.results['file_security']['valid_files'] = valid_file_tests
        
        # Test 2: Malicious file detection
        print("2. Testing malicious file detection...")
        
        malicious_file_tests = []
        
        # Test executable file disguised as image
        try:
            malicious_content = b'MZ\x90\x00\x03\x00\x00\x00'  # PE executable header
            malicious_file = SimpleUploadedFile(
                "malicious.jpg",
                malicious_content,
                content_type="image/jpeg"
            )
            
            validate_file_security_enhanced(malicious_file)
            
            malicious_file_tests.append({
                'attack_type': 'Executable disguised as image',
                'filename': 'malicious.jpg',
                'detected': False,
                'error': 'Should have been blocked'
            })
            
        except ValidationError as e:
            malicious_file_tests.append({
                'attack_type': 'Executable disguised as image',
                'filename': 'malicious.jpg',
                'detected': True,
                'error': str(e)
            })
        
        # Test script injection
        try:
            script_content = b'<script>alert("XSS")</script>'
            script_file = SimpleUploadedFile(
                "script.txt",
                script_content,
                content_type="text/plain"
            )
            
            validate_file_security_enhanced(script_file)
            
            malicious_file_tests.append({
                'attack_type': 'Script injection in text file',
                'filename': 'script.txt',
                'detected': False,
                'error': 'Should have been blocked'
            })
            
        except ValidationError as e:
            malicious_file_tests.append({
                'attack_type': 'Script injection in text file',
                'filename': 'script.txt',
                'detected': True,
                'error': str(e)
            })
        
        self.results['file_security']['malicious_files'] = malicious_file_tests
        
        print("✓ File upload security analysis complete")
    
    def analyze_payment_models(self):
        """Analyze payment model structure and validation"""
        print("\n=== ANALYZING PAYMENT MODELS ===")
        
        model_analysis = {}
        
        # Analyze Deal model
        print("1. Analyzing Deal model...")
        
        deal_fields = []
        for field in Deal._meta.fields:
            field_info = {
                'name': field.name,
                'type': field.__class__.__name__,
                'null': field.null,
                'blank': field.blank,
                'max_length': getattr(field, 'max_length', None),
                'max_digits': getattr(field, 'max_digits', None),
                'decimal_places': getattr(field, 'decimal_places', None)
            }
            deal_fields.append(field_info)
        
        model_analysis['deal_model'] = {
            'fields': deal_fields,
            'has_financial_validation': hasattr(Deal, 'validate_financial_fields'),
            'has_state_machine': hasattr(Deal, 'validate_payment_status_transition'),
            'has_optimistic_locking': hasattr(Deal, 'lock_version')
        }
        
        # Analyze Payment model
        print("2. Analyzing Payment model...")
        
        payment_fields = []
        for field in Payment._meta.fields:
            field_info = {
                'name': field.name,
                'type': field.__class__.__name__,
                'null': field.null,
                'blank': field.blank,
                'max_length': getattr(field, 'max_length', None),
                'max_digits': getattr(field, 'max_digits', None),
                'decimal_places': getattr(field, 'decimal_places', None)
            }
            payment_fields.append(field_info)
        
        model_analysis['payment_model'] = {
            'fields': payment_fields,
            'has_financial_validation': hasattr(Payment, 'validate_financial_fields'),
            'has_file_security': any(f.name == 'receipt_file' for f in Payment._meta.fields),
            'has_transaction_id': any(f.name == 'transaction_id' for f in Payment._meta.fields)
        }
        
        # Check model relationships
        print("3. Analyzing model relationships...")
        
        relationships = {
            'payment_to_deal': Payment._meta.get_field('deal').related_model == Deal,
            'payment_invoice_exists': PaymentInvoice is not None,
            'payment_approval_exists': PaymentApproval is not None,
            'one_to_one_invoice': hasattr(Payment, 'invoice'),
            'many_to_many_approvals': hasattr(Payment, 'approvals')
        }
        
        model_analysis['relationships'] = relationships
        
        self.results['system_validation'] = model_analysis
        
        print("✓ Payment models analysis complete")
    
    def generate_summary_report(self):
        """Generate comprehensive summary report"""
        print("\n=== GENERATING SUMMARY REPORT ===")
        
        # Count test results
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        
        # Financial calculations summary
        if 'precision_tests' in self.results['financial_calculations']:
            precision_tests = self.results['financial_calculations']['precision_tests']
            total_tests += len(precision_tests)
            passed_tests += sum(1 for t in precision_tests if t['passed'])
            failed_tests += sum(1 for t in precision_tests if not t['passed'])
        
        if 'consistency_tests' in self.results['financial_calculations']:
            consistency_tests = self.results['financial_calculations']['consistency_tests']
            total_tests += len(consistency_tests)
            passed_tests += sum(1 for t in consistency_tests if t['fully_paid_match'] and t['overpaid_match'])
            failed_tests += sum(1 for t in consistency_tests if not (t['fully_paid_match'] and t['overpaid_match']))
        
        if 'commission_tests' in self.results['financial_calculations']:
            commission_tests = self.results['financial_calculations']['commission_tests']
            total_tests += len(commission_tests)
            passed_tests += sum(1 for t in commission_tests if t['accurate'])
            failed_tests += sum(1 for t in commission_tests if not t['accurate'])
        
        # File security summary
        if 'valid_files' in self.results['file_security']:
            file_tests = self.results['file_security']['valid_files']
            total_tests += len(file_tests)
            passed_tests += sum(1 for t in file_tests if t['validation_passed'])
            failed_tests += sum(1 for t in file_tests if not t['validation_passed'])
        
        if 'malicious_files' in self.results['file_security']:
            malicious_tests = self.results['file_security']['malicious_files']
            total_tests += len(malicious_tests)
            passed_tests += sum(1 for t in malicious_tests if t['detected'])
            failed_tests += sum(1 for t in malicious_tests if not t['detected'])
        
        # Generate recommendations
        recommendations = []
        
        # Check precision test failures
        if 'precision_tests' in self.results['financial_calculations']:
            failed_precision = [t for t in self.results['financial_calculations']['precision_tests'] if not t['passed']]
            if failed_precision:
                recommendations.append("Review decimal precision validation - some test cases failed")
        
        # Check transaction ID analysis
        if 'transaction_analysis' in self.results:
            txn_analysis = self.results['transaction_analysis']
            if 'transaction_ids' in txn_analysis:
                if txn_analysis['transaction_ids'].get('has_duplicates'):
                    recommendations.append("Duplicate transaction IDs found - review ID generation logic")
        
        # Check file security
        if 'malicious_files' in self.results['file_security']:
            undetected_threats = [t for t in self.results['file_security']['malicious_files'] if not t['detected']]
            if undetected_threats:
                recommendations.append("File security validation needs strengthening - some threats not detected")
        
        # Check model validation
        if 'system_validation' in self.results:
            model_analysis = self.results['system_validation']
            if not model_analysis.get('deal_model', {}).get('has_financial_validation'):
                recommendations.append("Deal model missing financial validation mixin")
            if not model_analysis.get('payment_model', {}).get('has_financial_validation'):
                recommendations.append("Payment model missing financial validation mixin")
        
        # Summary
        summary = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            'recommendations': recommendations,
            'critical_issues': failed_tests > 0,
            'overall_status': 'PASS' if failed_tests == 0 else 'FAIL'
        }
        
        self.results['summary'] = summary
        
        return summary
    
    def run_complete_analysis(self):
        """Run complete payment processing system analysis"""
        print("PAYMENT PROCESSING SYSTEM ANALYSIS")
        print("=" * 50)
        
        try:
            # Run all analysis components
            self.analyze_financial_calculations()
            self.analyze_existing_transactions()
            self.analyze_file_upload_security()
            self.analyze_payment_models()
            
            # Generate summary
            summary = self.generate_summary_report()
            
            print(f"\n=== ANALYSIS COMPLETE ===")
            print(f"Total Tests: {summary['total_tests']}")
            print(f"Passed: {summary['passed_tests']}")
            print(f"Failed: {summary['failed_tests']}")
            print(f"Success Rate: {summary['success_rate']:.1f}%")
            print(f"Overall Status: {summary['overall_status']}")
            
            if summary['recommendations']:
                print(f"\nRecommendations:")
                for i, rec in enumerate(summary['recommendations'], 1):
                    print(f"{i}. {rec}")
            
            return self.results
            
        except Exception as e:
            print(f"Analysis failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

def main():
    """Main execution function"""
    print("Starting Payment Processing System Analysis...")
    
    analyzer = PaymentProcessingAnalysis()
    results = analyzer.run_complete_analysis()
    
    if results:
        # Save results to file
        import json
        
        # Convert Decimal objects to strings for JSON serialization
        def decimal_converter(obj):
            if isinstance(obj, Decimal):
                return str(obj)
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        with open('payment_processing_analysis_results.json', 'w') as f:
            json.dump(results, f, indent=2, default=decimal_converter)
        
        print(f"\nDetailed results saved to: payment_processing_analysis_results.json")
        
        return results['summary']['overall_status'] == 'PASS'
    
    return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)