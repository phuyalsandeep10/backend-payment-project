#!/usr/bin/env python3
"""
Payment Processing System Analysis
Comprehensive analysis of payment model financial calculations, validation, 
approval workflows, transaction ID generation, and file upload security.

Task 3: Payment Processing System Analysis
- Validate payment model financial calculations and precision
- Test payment creation, validation, and approval workflows  
- Analyze transaction ID generation and uniqueness
- Examine file upload security for payment receipts
"""

import os
import sys
import django
import uuid
import tempfile
import io
from decimal import Decimal
from datetime import datetime, timedelta
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError
from django.db import transaction, IntegrityError
from django.test import TestCase
from django.contrib.auth import get_user_model

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from deals.models import Deal, Payment, PaymentInvoice, PaymentApproval
from deals.financial_optimizer import FinancialFieldOptimizer, FinancialValidationMixin
from deals.atomic_operations import AtomicFinancialOperations
from clients.models import Client
from organization.models import Organization
from authentication.models import User
from core_config.file_security import validate_file_security_enhanced

class PaymentProcessingAnalysis:
    """Comprehensive analysis of payment processing system"""
    
    def __init__(self):
        self.results = {
            'financial_calculations': {},
            'payment_workflows': {},
            'transaction_ids': {},
            'file_security': {},
            'validation_tests': {},
            'performance_metrics': {},
            'security_analysis': {},
            'issues_found': [],
            'recommendations': []
        }
        
        # Setup test data
        self.setup_test_environment()
    
    def setup_test_environment(self):
        """Setup test organization, users, and clients"""
        print("Setting up test environment...")
        
        # Create test organization
        self.organization, _ = Organization.objects.get_or_create(
            name="Test Payment Org",
            defaults={
                'description': "Test organization for payment analysis",
                'is_active': True,
                'sales_goal': 100000.00
            }
        )
        
        # Create test users
        User = get_user_model()
        self.salesperson, _ = User.objects.get_or_create(
            email="salesperson@test.com",
            defaults={
                'first_name': "Sales",
                'last_name': "Person",
                'organization': self.organization,
                'is_active': True
            }
        )
        
        self.verifier, _ = User.objects.get_or_create(
            email="verifier@test.com", 
            defaults={
                'first_name': "Verifier",
                'last_name': "User",
                'organization': self.organization,
                'is_active': True
            }
        )
        
        # Create test client
        self.client, _ = Client.objects.get_or_create(
            email="client@test.com",
            organization=self.organization,
            defaults={
                'client_name': "Test Payment Client",
                'phone_number': "+1234567890",
                'nationality': "Test Country",
                'created_by': self.salesperson
            }
        )
        
        print("✓ Test environment setup complete")
    
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
            },
            {
                'payments': [{'amount': Decimal('5000.01')}],
                'description': 'Slight overpayment (within tolerance)',
                'expected_fully_paid': True,
                'expected_overpaid': False
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
    
    def analyze_payment_workflows(self):
        """Test payment creation, validation, and approval workflows"""
        print("\n=== ANALYZING PAYMENT WORKFLOWS ===")
        
        # Test 1: Payment creation workflow
        print("1. Testing payment creation workflow...")
        
        # Create test deal
        test_deal = Deal.objects.create(
            deal_id="TEST-PAYMENT-001",
            organization=self.organization,
            client=self.client,
            created_by=self.salesperson,
            payment_status='initial payment',
            deal_name="Test Payment Deal",
            deal_value=Decimal('3000.00'),
            currency='USD',
            payment_method='bank',
            source_type='linkedin',
            verification_status='pending'
        )
        
        # Test payment creation scenarios
        payment_creation_tests = []
        
        # Valid payment creation
        try:
            payment1 = Payment.objects.create(
                deal=test_deal,
                payment_date=datetime.now().date(),
                received_amount=Decimal('1500.00'),
                payment_type='bank',
                payment_category='partial',
                payment_remarks='First payment'
            )
            
            payment_creation_tests.append({
                'scenario': 'Valid partial payment',
                'amount': str(payment1.received_amount),
                'success': True,
                'transaction_id': payment1.transaction_id,
                'error': None
            })
            
        except Exception as e:
            payment_creation_tests.append({
                'scenario': 'Valid partial payment',
                'success': False,
                'error': str(e)
            })
        
        # Test overpayment validation
        try:
            payment2 = Payment.objects.create(
                deal=test_deal,
                payment_date=datetime.now().date(),
                received_amount=Decimal('2000.00'),  # Would exceed deal value
                payment_type='bank',
                payment_category='final'
            )
            
            payment_creation_tests.append({
                'scenario': 'Overpayment attempt',
                'amount': '2000.00',
                'success': True,  # Should fail
                'error': 'Should have been rejected'
            })
            
        except ValidationError as e:
            payment_creation_tests.append({
                'scenario': 'Overpayment attempt',
                'amount': '2000.00', 
                'success': False,
                'error': str(e),
                'correctly_rejected': True
            })
        
        self.results['payment_workflows']['creation_tests'] = payment_creation_tests
        
        # Test 2: Payment state transitions
        print("2. Testing payment state transitions...")
        
        # Test deal payment status updates
        initial_status = test_deal.payment_status
        test_deal.refresh_from_db()
        
        state_transition_tests = [{
            'initial_status': initial_status,
            'current_status': test_deal.payment_status,
            'total_paid': test_deal.get_total_paid_amount(),
            'deal_value': float(test_deal.deal_value),
            'remaining_balance': test_deal.get_remaining_balance(),
            'payment_progress': test_deal.get_payment_progress()
        }]
        
        self.results['payment_workflows']['state_transitions'] = state_transition_tests
        
        # Test 3: Invoice generation workflow
        print("3. Testing invoice generation workflow...")
        
        invoice_tests = []
        payments = Payment.objects.filter(deal=test_deal)
        
        for payment in payments:
            try:
                # Check if invoice was auto-created (via signals)
                invoice = PaymentInvoice.objects.get(payment=payment)
                
                invoice_tests.append({
                    'payment_id': payment.id,
                    'invoice_id': invoice.invoice_id,
                    'invoice_created': True,
                    'invoice_status': invoice.invoice_status,
                    'auto_generated': True
                })
                
            except PaymentInvoice.DoesNotExist:
                # Manually create invoice if not auto-generated
                invoice = PaymentInvoice.objects.create(
                    payment=payment,
                    deal=test_deal
                )
                
                invoice_tests.append({
                    'payment_id': payment.id,
                    'invoice_id': invoice.invoice_id,
                    'invoice_created': True,
                    'invoice_status': invoice.invoice_status,
                    'auto_generated': False
                })
        
        self.results['payment_workflows']['invoice_tests'] = invoice_tests
        
        # Test 4: Approval workflow
        print("4. Testing approval workflow...")
        
        approval_tests = []
        
        for payment in payments:
            try:
                # Create payment approval
                approval = PaymentApproval.objects.create(
                    payment=payment,
                    deal=test_deal,
                    approved_by=self.verifier,
                    verifier_remarks='Payment verified and approved',
                    amount_in_invoice=payment.received_amount
                )
                
                approval_tests.append({
                    'payment_id': payment.id,
                    'approval_created': True,
                    'approved_by': approval.approved_by.email,
                    'approval_date': approval.approval_date.isoformat(),
                    'amount_verified': str(approval.amount_in_invoice)
                })
                
            except Exception as e:
                approval_tests.append({
                    'payment_id': payment.id,
                    'approval_created': False,
                    'error': str(e)
                })
        
        self.results['payment_workflows']['approval_tests'] = approval_tests
        
        print("✓ Payment workflows analysis complete")
    
    def analyze_transaction_id_generation(self):
        """Analyze transaction ID generation and uniqueness"""
        print("\n=== ANALYZING TRANSACTION ID GENERATION ===")
        
        # Test 1: Transaction ID format and uniqueness
        print("1. Testing transaction ID generation...")
        
        # Create multiple payments to test ID generation
        test_deal = Deal.objects.filter(organization=self.organization).first()
        if not test_deal:
            test_deal = Deal.objects.create(
                deal_id="TXN-TEST-001",
                organization=self.organization,
                client=self.client,
                created_by=self.salesperson,
                payment_status='initial payment',
                deal_name="Transaction ID Test Deal",
                deal_value=Decimal('1000.00'),
                currency='USD',
                payment_method='bank',
                source_type='linkedin'
            )
        
        transaction_id_tests = []
        generated_ids = set()
        
        # Generate multiple payments to test uniqueness
        for i in range(10):
            try:
                payment = Payment.objects.create(
                    deal=test_deal,
                    payment_date=datetime.now().date(),
                    received_amount=Decimal('10.00'),  # Small amounts to avoid exceeding deal value
                    payment_type='bank',
                    payment_category='partial',
                    payment_remarks=f'Test payment {i+1}'
                )
                
                transaction_id_tests.append({
                    'payment_number': i + 1,
                    'transaction_id': payment.transaction_id,
                    'format_valid': payment.transaction_id.startswith('TXN-'),
                    'length_valid': len(payment.transaction_id) >= 8,
                    'unique': payment.transaction_id not in generated_ids
                })
                
                generated_ids.add(payment.transaction_id)
                
            except Exception as e:
                transaction_id_tests.append({
                    'payment_number': i + 1,
                    'error': str(e),
                    'failed': True
                })
        
        self.results['transaction_ids']['generation_tests'] = transaction_id_tests
        
        # Test 2: Concurrent transaction ID generation
        print("2. Testing concurrent transaction ID generation...")
        
        concurrent_tests = []
        
        # Simulate concurrent payment creation
        try:
            with transaction.atomic():
                # Create multiple payments in quick succession
                concurrent_payments = []
                for i in range(5):
                    payment = Payment(
                        deal=test_deal,
                        payment_date=datetime.now().date(),
                        received_amount=Decimal('5.00'),
                        payment_type='bank',
                        payment_category='partial'
                    )
                    concurrent_payments.append(payment)
                
                # Save all at once to test race conditions
                Payment.objects.bulk_create(concurrent_payments)
                
                # Check for duplicate transaction IDs
                created_payments = Payment.objects.filter(
                    deal=test_deal,
                    received_amount=Decimal('5.00')
                ).order_by('-id')[:5]
                
                txn_ids = [p.transaction_id for p in created_payments]
                unique_ids = set(txn_ids)
                
                concurrent_tests.append({
                    'payments_created': len(created_payments),
                    'transaction_ids': txn_ids,
                    'unique_count': len(unique_ids),
                    'no_duplicates': len(txn_ids) == len(unique_ids),
                    'all_have_ids': all(tid for tid in txn_ids)
                })
                
        except Exception as e:
            concurrent_tests.append({
                'error': str(e),
                'failed': True
            })
        
        self.results['transaction_ids']['concurrent_tests'] = concurrent_tests
        
        # Test 3: Transaction ID sequence validation
        print("3. Testing transaction ID sequence...")
        
        # Get recent transaction IDs to check sequence
        recent_payments = Payment.objects.filter(
            transaction_id__startswith='TXN-'
        ).order_by('-id')[:10]
        
        sequence_tests = []
        for payment in recent_payments:
            try:
                # Extract numeric part
                numeric_part = payment.transaction_id.split('-')[1]
                is_numeric = numeric_part.isdigit()
                is_padded = len(numeric_part) == 4
                
                sequence_tests.append({
                    'transaction_id': payment.transaction_id,
                    'numeric_part': numeric_part,
                    'is_numeric': is_numeric,
                    'is_padded': is_padded,
                    'valid_format': is_numeric and is_padded
                })
                
            except Exception as e:
                sequence_tests.append({
                    'transaction_id': payment.transaction_id,
                    'error': str(e),
                    'valid_format': False
                })
        
        self.results['transaction_ids']['sequence_tests'] = sequence_tests
        
        print("✓ Transaction ID analysis complete")
    
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
        
        # Test PHP code injection
        try:
            php_content = b'<?php system($_GET["cmd"]); ?>'
            php_file = SimpleUploadedFile(
                "innocent.jpg",
                php_content,
                content_type="image/jpeg"
            )
            
            validate_file_security_enhanced(php_file)
            
            malicious_file_tests.append({
                'attack_type': 'PHP code in image file',
                'filename': 'innocent.jpg',
                'detected': False,
                'error': 'Should have been blocked'
            })
            
        except ValidationError as e:
            malicious_file_tests.append({
                'attack_type': 'PHP code in image file',
                'filename': 'innocent.jpg',
                'detected': True,
                'error': str(e)
            })
        
        self.results['file_security']['malicious_files'] = malicious_file_tests
        
        # Test 3: File size limits
        print("3. Testing file size limits...")
        
        size_limit_tests = []
        
        # Test oversized file
        try:
            large_content = b'A' * (11 * 1024 * 1024)  # 11MB file
            large_file = SimpleUploadedFile(
                "large_receipt.jpg",
                large_content,
                content_type="image/jpeg"
            )
            
            validate_file_security_enhanced(large_file)
            
            size_limit_tests.append({
                'test_type': 'Oversized image file',
                'file_size': len(large_content),
                'limit_enforced': False,
                'error': 'Should have been rejected'
            })
            
        except ValidationError as e:
            size_limit_tests.append({
                'test_type': 'Oversized image file',
                'file_size': len(large_content),
                'limit_enforced': True,
                'error': str(e)
            })
        
        self.results['file_security']['size_limits'] = size_limit_tests
        
        # Test 4: File extension validation
        print("4. Testing file extension validation...")
        
        extension_tests = []
        
        # Test invalid extensions
        invalid_extensions = ['.exe', '.bat', '.php', '.asp', '.jsp', '.sh']
        
        for ext in invalid_extensions:
            try:
                invalid_file = SimpleUploadedFile(
                    f"test{ext}",
                    b"test content",
                    content_type="application/octet-stream"
                )
                
                validate_file_security_enhanced(invalid_file)
                
                extension_tests.append({
                    'extension': ext,
                    'blocked': False,
                    'error': 'Should have been blocked'
                })
                
            except ValidationError as e:
                extension_tests.append({
                    'extension': ext,
                    'blocked': True,
                    'error': str(e)
                })
        
        self.results['file_security']['extension_tests'] = extension_tests
        
        print("✓ File upload security analysis complete")
    
    def analyze_atomic_operations(self):
        """Test atomic payment operations and race condition handling"""
        print("\n=== ANALYZING ATOMIC OPERATIONS ===")
        
        # Test atomic payment creation
        print("1. Testing atomic payment creation...")
        
        test_deal = Deal.objects.filter(organization=self.organization).first()
        
        atomic_tests = []
        
        try:
            # Test atomic payment creation
            result = AtomicFinancialOperations.atomic_payment_creation(
                str(test_deal.id),
                {
                    'received_amount': Decimal('100.00'),
                    'payment_type': 'bank',
                    'payment_category': 'partial',
                    'payment_remarks': 'Atomic test payment'
                },
                user=self.salesperson
            )
            
            atomic_tests.append({
                'operation': 'atomic_payment_creation',
                'success': True,
                'payment_id': result['payment_id'],
                'amount': result['amount'],
                'deal_status': result['deal_payment_status']
            })
            
        except Exception as e:
            atomic_tests.append({
                'operation': 'atomic_payment_creation',
                'success': False,
                'error': str(e)
            })
        
        self.results['payment_workflows']['atomic_operations'] = atomic_tests
        
        print("✓ Atomic operations analysis complete")
    
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
        
        # Payment workflows summary
        if 'creation_tests' in self.results['payment_workflows']:
            creation_tests = self.results['payment_workflows']['creation_tests']
            total_tests += len(creation_tests)
            passed_tests += sum(1 for t in creation_tests if t['success'])
            failed_tests += sum(1 for t in creation_tests if not t['success'])
        
        # Transaction ID summary
        if 'generation_tests' in self.results['transaction_ids']:
            txn_tests = self.results['transaction_ids']['generation_tests']
            total_tests += len(txn_tests)
            passed_tests += sum(1 for t in txn_tests if not t.get('failed', False))
            failed_tests += sum(1 for t in txn_tests if t.get('failed', False))
        
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
        
        # Check transaction ID uniqueness
        if 'concurrent_tests' in self.results['transaction_ids']:
            concurrent_results = self.results['transaction_ids']['concurrent_tests']
            for test in concurrent_results:
                if not test.get('no_duplicates', True):
                    recommendations.append("Transaction ID generation may have race condition issues")
        
        # Check file security
        if 'malicious_files' in self.results['file_security']:
            undetected_threats = [t for t in self.results['file_security']['malicious_files'] if not t['detected']]
            if undetected_threats:
                recommendations.append("File security validation needs strengthening - some threats not detected")
        
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
            self.analyze_payment_workflows()
            self.analyze_transaction_id_generation()
            self.analyze_file_upload_security()
            self.analyze_atomic_operations()
            
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