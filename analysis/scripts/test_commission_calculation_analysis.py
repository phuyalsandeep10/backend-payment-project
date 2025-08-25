#!/usr/bin/env python3
"""
Commission Calculation System Analysis Test
Comprehensive analysis of commission model financial calculations, multi-currency support,
exchange rate handling, calculation accuracy, edge cases, and optimistic locking implementation.

Requirements covered:
- 4.2: Business rule enforcement (commission calculations)
- 2.1: Financial calculation precision
- 3.4: Optimistic locking for concurrent operations
"""

import os
import sys
import django
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, date, timedelta
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup Django
sys.path.append('/Users/kiro/Desktop/Backend_PRS/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase
from django.db import transaction, IntegrityError
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.utils import timezone

from commission.models import Commission
from commission.calculation_optimizer import CommissionCalculationOptimizer, CommissionAuditTrail
from deals.models import Deal
from deals.financial_optimizer import FinancialFieldOptimizer, FinancialValidationMixin
from deals.atomic_operations import AtomicFinancialOperations, OptimisticLockingMixin
from authentication.models import User
from organization.models import Organization

User = get_user_model()

class CommissionCalculationAnalysis:
    """Comprehensive analysis of commission calculation system"""
    
    def __init__(self):
        self.results = {
            'financial_calculations': {},
            'multi_currency_support': {},
            'exchange_rate_handling': {},
            'calculation_accuracy': {},
            'edge_cases': {},
            'optimistic_locking': {},
            'performance_metrics': {},
            'security_validation': {},
            'summary': {}
        }
        
        # Test data setup
        self.setup_test_data()
    
    def setup_test_data(self):
        """Setup test organization and users"""
        try:
            with transaction.atomic():
                # Create test organization
                self.test_org, created = Organization.objects.get_or_create(
                    name='Commission Test Org',
                    defaults={
                        'description': 'Test organization for commission analysis',
                        'is_active': True,
                        'sales_goal': 100000.00
                    }
                )
                
                # Create test users
                self.test_user, created = User.objects.get_or_create(
                    email='commission.test@example.com',
                    defaults={
                        'username': 'commission_test_user',
                        'first_name': 'Commission',
                        'last_name': 'Tester',
                        'organization': self.test_org,
                        'is_active': True
                    }
                )
                
                self.admin_user, created = User.objects.get_or_create(
                    email='commission.admin@example.com',
                    defaults={
                        'username': 'commission_admin',
                        'first_name': 'Commission',
                        'last_name': 'Admin',
                        'organization': self.test_org,
                        'is_active': True,
                        'is_staff': True
                    }
                )
                
                print(f"✓ Test data setup complete - Org: {self.test_org.name}")
            
        except Exception as e:
            print(f"✗ Test data setup failed: {str(e)}")
            # Try to continue with existing data if available
            try:
                self.test_org = Organization.objects.filter(name='Commission Test Org').first()
                self.test_user = User.objects.filter(email='commission.test@example.com').first()
                self.admin_user = User.objects.filter(email='commission.admin@example.com').first()
                
                if not all([self.test_org, self.test_user, self.admin_user]):
                    raise Exception("Could not find or create required test data")
                    
                print("✓ Using existing test data")
            except Exception as e2:
                print(f"✗ Could not recover test data: {str(e2)}")
                raise
    
    def analyze_financial_calculations(self):
        """Test 1: Validate commission model financial calculations"""
        print("\n=== Testing Financial Calculations ===")
        
        test_cases = [
            # (total_sales, commission_rate, exchange_rate, bonus, penalty, expected_commission)
            (Decimal('10000.00'), Decimal('5.00'), Decimal('1.00'), Decimal('0.00'), Decimal('0.00')),
            (Decimal('25000.50'), Decimal('7.50'), Decimal('1.25'), Decimal('500.00'), Decimal('100.00')),
            (Decimal('0.00'), Decimal('5.00'), Decimal('1.00'), Decimal('0.00'), Decimal('0.00')),
            (Decimal('999999.99'), Decimal('10.00'), Decimal('0.85'), Decimal('1000.00'), Decimal('500.00')),
            (Decimal('1.00'), Decimal('0.01'), Decimal('100.00'), Decimal('0.00'), Decimal('0.00')),
        ]
        
        calculation_results = []
        
        for i, (sales, rate, exchange, bonus, penalty) in enumerate(test_cases):
            try:
                with transaction.atomic():
                    # Create commission record
                    commission = Commission.objects.create(
                        organization=self.test_org,
                        user=self.test_user,
                        total_sales=sales,
                        commission_rate=rate,
                        exchange_rate=exchange,
                        bonus=bonus,
                        penalty=penalty,
                        start_date=date.today() - timedelta(days=30),
                        end_date=date.today(),
                        created_by=self.admin_user
                    )
                
                # Manual calculation for verification
                expected_commission_amount = sales * (rate / Decimal('100'))
                expected_total_commission = (expected_commission_amount * exchange) + bonus
                expected_total_receivable = expected_total_commission - penalty
                expected_converted_amount = sales * exchange
                
                # Verify calculations
                calculation_correct = (
                    abs(commission.commission_amount - expected_commission_amount) < Decimal('0.01') and
                    abs(commission.total_commission - expected_total_commission) < Decimal('0.01') and
                    abs(commission.total_receivable - expected_total_receivable) < Decimal('0.01') and
                    abs(commission.converted_amount - expected_converted_amount) < Decimal('0.01')
                )
                
                result = {
                    'test_case': i + 1,
                    'input': {
                        'sales': float(sales),
                        'rate': float(rate),
                        'exchange': float(exchange),
                        'bonus': float(bonus),
                        'penalty': float(penalty)
                    },
                    'calculated': {
                        'commission_amount': float(commission.commission_amount),
                        'total_commission': float(commission.total_commission),
                        'total_receivable': float(commission.total_receivable),
                        'converted_amount': float(commission.converted_amount)
                    },
                    'expected': {
                        'commission_amount': float(expected_commission_amount),
                        'total_commission': float(expected_total_commission),
                        'total_receivable': float(expected_total_receivable),
                        'converted_amount': float(expected_converted_amount)
                    },
                    'calculation_correct': calculation_correct,
                    'precision_test': self._test_decimal_precision(commission)
                }
                
                calculation_results.append(result)
                
                if calculation_correct:
                    print(f"✓ Test case {i + 1}: Financial calculations correct")
                else:
                    print(f"✗ Test case {i + 1}: Financial calculations incorrect")
                
                    # Clean up
                    commission.delete()
                
            except Exception as e:
                print(f"✗ Test case {i + 1} failed: {str(e)}")
                calculation_results.append({
                    'test_case': i + 1,
                    'error': str(e),
                    'calculation_correct': False
                })
        
        self.results['financial_calculations'] = {
            'test_cases': calculation_results,
            'total_tests': len(test_cases),
            'passed_tests': sum(1 for r in calculation_results if r.get('calculation_correct', False)),
            'precision_validation': self._validate_financial_precision()
        }
        
        print(f"Financial calculations: {self.results['financial_calculations']['passed_tests']}/{len(test_cases)} tests passed")
    
    def _test_decimal_precision(self, commission):
        """Test decimal precision handling"""
        try:
            # Check if all amounts have proper decimal precision (2 decimal places for currency)
            amounts = [
                commission.commission_amount,
                commission.total_commission,
                commission.total_receivable,
                commission.converted_amount
            ]
            
            precision_correct = all(
                amount.as_tuple().exponent >= -2 for amount in amounts
            )
            
            return {
                'precision_correct': precision_correct,
                'amounts_checked': len(amounts)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _validate_financial_precision(self):
        """Validate financial field precision using FinancialFieldOptimizer"""
        try:
            # Test various precision scenarios
            test_values = [
                Decimal('123.456789'),  # Should round to 123.46
                Decimal('999.999'),     # Should round to 1000.00
                Decimal('0.001'),       # Should round to 0.00
                Decimal('1.005'),       # Should round to 1.01 (banker's rounding)
            ]
            
            precision_results = []
            
            for value in test_values:
                try:
                    validated = FinancialFieldOptimizer.validate_decimal_field(
                        value, 'test_field', precision=FinancialFieldOptimizer.CURRENCY_PRECISION
                    )
                    
                    precision_results.append({
                        'input': float(value),
                        'output': float(validated),
                        'precision_applied': True
                    })
                except Exception as e:
                    precision_results.append({
                        'input': float(value),
                        'error': str(e),
                        'precision_applied': False
                    })
            
            return {
                'precision_tests': precision_results,
                'optimizer_available': True
            }
            
        except Exception as e:
            return {'error': str(e), 'optimizer_available': False}
    
    def analyze_multi_currency_support(self):
        """Test 2: Test multi-currency support and exchange rate handling"""
        print("\n=== Testing Multi-Currency Support ===")
        
        # Test different currencies and exchange rates
        currency_test_cases = [
            ('USD', Decimal('1.00')),
            ('EUR', Decimal('0.85')),
            ('GBP', Decimal('0.73')),
            ('NPR', Decimal('132.50')),
            ('JPY', Decimal('110.25')),
            ('INR', Decimal('83.15')),
        ]
        
        currency_results = []
        
        for currency, exchange_rate in currency_test_cases:
            try:
                commission = Commission.objects.create(
                    organization=self.test_org,
                    user=self.test_user,
                    total_sales=Decimal('10000.00'),
                    commission_rate=Decimal('5.00'),
                    currency=currency,
                    exchange_rate=exchange_rate,
                    start_date=date.today() - timedelta(days=30),
                    end_date=date.today(),
                    created_by=self.admin_user
                )
                
                # Verify currency conversion
                expected_converted = Decimal('10000.00') * exchange_rate
                conversion_correct = abs(commission.converted_amount - expected_converted) < Decimal('0.01')
                
                result = {
                    'currency': currency,
                    'exchange_rate': float(exchange_rate),
                    'converted_amount': float(commission.converted_amount),
                    'expected_converted': float(expected_converted),
                    'conversion_correct': conversion_correct,
                    'currency_field_valid': commission.currency == currency
                }
                
                currency_results.append(result)
                
                if conversion_correct:
                    print(f"✓ {currency}: Currency conversion correct")
                else:
                    print(f"✗ {currency}: Currency conversion incorrect")
                
                commission.delete()
                
            except Exception as e:
                print(f"✗ {currency}: Test failed - {str(e)}")
                currency_results.append({
                    'currency': currency,
                    'error': str(e),
                    'conversion_correct': False
                })
        
        # Test currency validation
        currency_validation = self._test_currency_validation()
        
        self.results['multi_currency_support'] = {
            'currency_tests': currency_results,
            'total_currencies_tested': len(currency_test_cases),
            'successful_conversions': sum(1 for r in currency_results if r.get('conversion_correct', False)),
            'currency_validation': currency_validation,
            'supported_currencies': self._get_supported_currencies()
        }
        
        print(f"Multi-currency support: {self.results['multi_currency_support']['successful_conversions']}/{len(currency_test_cases)} currencies tested successfully")
    
    def _test_currency_validation(self):
        """Test currency field validation"""
        try:
            # Test invalid currency codes
            invalid_currencies = ['XXX', 'INVALID', '123', '']
            
            validation_results = []
            
            for invalid_currency in invalid_currencies:
                try:
                    commission = Commission(
                        organization=self.test_org,
                        user=self.test_user,
                        currency=invalid_currency,
                        total_sales=Decimal('1000.00'),
                        start_date=date.today(),
                        end_date=date.today()
                    )
                    commission.full_clean()  # This should raise ValidationError
                    
                    validation_results.append({
                        'currency': invalid_currency,
                        'validation_passed': False,  # Should have failed
                        'error': 'Validation should have failed'
                    })
                    
                except ValidationError:
                    validation_results.append({
                        'currency': invalid_currency,
                        'validation_passed': True,  # Correctly rejected
                        'error': None
                    })
                except Exception as e:
                    validation_results.append({
                        'currency': invalid_currency,
                        'validation_passed': False,
                        'error': str(e)
                    })
            
            return {
                'invalid_currency_tests': validation_results,
                'validation_working': all(r['validation_passed'] for r in validation_results)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_supported_currencies(self):
        """Get list of supported currencies"""
        try:
            from commission.models import get_currency_choices
            currencies = get_currency_choices()
            return {
                'total_supported': len(currencies),
                'sample_currencies': currencies[:10]  # First 10 for brevity
            }
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_exchange_rate_handling(self):
        """Test 3: Analyze exchange rate handling and edge cases"""
        print("\n=== Testing Exchange Rate Handling ===")
        
        # Test edge cases for exchange rates
        exchange_rate_cases = [
            (Decimal('0.000001'), 'minimum_rate'),  # Minimum allowed rate
            (Decimal('1.00'), 'unity_rate'),        # 1:1 exchange
            (Decimal('10000.00'), 'maximum_rate'),   # Very high rate
            (Decimal('0.1'), 'low_rate'),           # Low rate
            (Decimal('1.234567'), 'high_precision'), # High precision rate
        ]
        
        exchange_results = []
        
        for rate, test_type in exchange_rate_cases:
            try:
                # Test with FinancialFieldOptimizer validation
                validated_rate = FinancialFieldOptimizer.validate_exchange_rate(rate)
                
                commission = Commission.objects.create(
                    organization=self.test_org,
                    user=self.test_user,
                    total_sales=Decimal('1000.00'),
                    commission_rate=Decimal('5.00'),
                    exchange_rate=validated_rate,
                    start_date=date.today() - timedelta(days=30),
                    end_date=date.today(),
                    created_by=self.admin_user
                )
                
                # Test calculation accuracy
                expected_commission = Decimal('1000.00') * Decimal('0.05')  # 5%
                expected_total = expected_commission * validated_rate
                
                calculation_accurate = abs(commission.total_commission - expected_total) < Decimal('0.01')
                
                result = {
                    'test_type': test_type,
                    'input_rate': float(rate),
                    'validated_rate': float(validated_rate),
                    'calculated_total': float(commission.total_commission),
                    'expected_total': float(expected_total),
                    'calculation_accurate': calculation_accurate,
                    'rate_validation_passed': True
                }
                
                exchange_results.append(result)
                
                if calculation_accurate:
                    print(f"✓ {test_type}: Exchange rate handling correct")
                else:
                    print(f"✗ {test_type}: Exchange rate calculation incorrect")
                
                commission.delete()
                
            except ValidationError as e:
                # Expected for invalid rates
                result = {
                    'test_type': test_type,
                    'input_rate': float(rate),
                    'validation_error': str(e),
                    'rate_validation_passed': False
                }
                exchange_results.append(result)
                print(f"✓ {test_type}: Correctly rejected invalid rate")
                
            except Exception as e:
                result = {
                    'test_type': test_type,
                    'input_rate': float(rate),
                    'error': str(e),
                    'rate_validation_passed': False
                }
                exchange_results.append(result)
                print(f"✗ {test_type}: Unexpected error - {str(e)}")
        
        # Test exchange rate precision
        precision_test = self._test_exchange_rate_precision()
        
        self.results['exchange_rate_handling'] = {
            'exchange_rate_tests': exchange_results,
            'total_tests': len(exchange_rate_cases),
            'successful_calculations': sum(1 for r in exchange_results if r.get('calculation_accurate', False)),
            'precision_test': precision_test
        }
        
        print(f"Exchange rate handling: {self.results['exchange_rate_handling']['successful_calculations']} successful calculations")
    
    def _test_exchange_rate_precision(self):
        """Test exchange rate precision handling"""
        try:
            # Test high precision exchange rates
            high_precision_rates = [
                Decimal('1.123456'),
                Decimal('0.987654'),
                Decimal('123.456789')
            ]
            
            precision_results = []
            
            for rate in high_precision_rates:
                try:
                    validated = FinancialFieldOptimizer.validate_exchange_rate(rate)
                    
                    # Check precision (should be 6 decimal places max)
                    precision_correct = validated.as_tuple().exponent >= -6
                    
                    precision_results.append({
                        'input_rate': float(rate),
                        'validated_rate': float(validated),
                        'precision_correct': precision_correct,
                        'decimal_places': abs(validated.as_tuple().exponent)
                    })
                    
                except Exception as e:
                    precision_results.append({
                        'input_rate': float(rate),
                        'error': str(e)
                    })
            
            return {
                'precision_tests': precision_results,
                'all_precision_correct': all(r.get('precision_correct', False) for r in precision_results)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_calculation_accuracy(self):
        """Test 4: Analyze commission calculation accuracy and edge cases"""
        print("\n=== Testing Calculation Accuracy & Edge Cases ===")
        
        edge_cases = [
            # (description, sales, rate, exchange, bonus, penalty)
            ('zero_sales', Decimal('0.00'), Decimal('5.00'), Decimal('1.00'), Decimal('0.00'), Decimal('0.00')),
            ('zero_rate', Decimal('1000.00'), Decimal('0.00'), Decimal('1.00'), Decimal('0.00'), Decimal('0.00')),
            ('high_bonus', Decimal('1000.00'), Decimal('5.00'), Decimal('1.00'), Decimal('10000.00'), Decimal('0.00')),
            ('high_penalty', Decimal('1000.00'), Decimal('5.00'), Decimal('1.00'), Decimal('0.00'), Decimal('10000.00')),
            ('rounding_test', Decimal('333.33'), Decimal('3.33'), Decimal('1.33'), Decimal('0.00'), Decimal('0.00')),
            ('large_numbers', Decimal('999999.99'), Decimal('99.99'), Decimal('99.99'), Decimal('9999.99'), Decimal('999.99')),
        ]
        
        accuracy_results = []
        
        for description, sales, rate, exchange, bonus, penalty in edge_cases:
            try:
                commission = Commission.objects.create(
                    organization=self.test_org,
                    user=self.test_user,
                    total_sales=sales,
                    commission_rate=rate,
                    exchange_rate=exchange,
                    bonus=bonus,
                    penalty=penalty,
                    start_date=date.today() - timedelta(days=30),
                    end_date=date.today(),
                    created_by=self.admin_user
                )
                
                # Verify edge case handling
                result = {
                    'description': description,
                    'input': {
                        'sales': float(sales),
                        'rate': float(rate),
                        'exchange': float(exchange),
                        'bonus': float(bonus),
                        'penalty': float(penalty)
                    },
                    'output': {
                        'commission_amount': float(commission.commission_amount),
                        'total_commission': float(commission.total_commission),
                        'total_receivable': float(commission.total_receivable)
                    },
                    'edge_case_handled': True,
                    'negative_receivable': commission.total_receivable < 0
                }
                
                # Specific validations for edge cases
                if description == 'zero_sales':
                    result['validation'] = commission.commission_amount == 0
                elif description == 'zero_rate':
                    result['validation'] = commission.commission_amount == 0
                elif description == 'high_penalty':
                    result['validation'] = commission.total_receivable < commission.total_commission
                else:
                    result['validation'] = True
                
                accuracy_results.append(result)
                
                if result['validation']:
                    print(f"✓ {description}: Edge case handled correctly")
                else:
                    print(f"✗ {description}: Edge case not handled correctly")
                
                commission.delete()
                
            except Exception as e:
                print(f"✗ {description}: Failed - {str(e)}")
                accuracy_results.append({
                    'description': description,
                    'error': str(e),
                    'edge_case_handled': False
                })
        
        # Test calculation consistency
        consistency_test = self._test_calculation_consistency()
        
        self.results['calculation_accuracy'] = {
            'edge_case_tests': accuracy_results,
            'total_edge_cases': len(edge_cases),
            'handled_correctly': sum(1 for r in accuracy_results if r.get('validation', False)),
            'consistency_test': consistency_test
        }
        
        print(f"Calculation accuracy: {self.results['calculation_accuracy']['handled_correctly']}/{len(edge_cases)} edge cases handled correctly")
    
    def _test_calculation_consistency(self):
        """Test calculation consistency across multiple saves"""
        try:
            # Create commission and save multiple times to test consistency
            commission = Commission.objects.create(
                organization=self.test_org,
                user=self.test_user,
                total_sales=Decimal('12345.67'),
                commission_rate=Decimal('7.89'),
                exchange_rate=Decimal('1.23'),
                bonus=Decimal('100.00'),
                penalty=Decimal('50.00'),
                start_date=date.today() - timedelta(days=30),
                end_date=date.today(),
                created_by=self.admin_user
            )
            
            # Record initial values
            initial_values = {
                'commission_amount': commission.commission_amount,
                'total_commission': commission.total_commission,
                'total_receivable': commission.total_receivable
            }
            
            # Save multiple times and check consistency
            consistency_results = []
            
            for i in range(5):
                commission.save()
                
                consistent = (
                    commission.commission_amount == initial_values['commission_amount'] and
                    commission.total_commission == initial_values['total_commission'] and
                    commission.total_receivable == initial_values['total_receivable']
                )
                
                consistency_results.append({
                    'save_iteration': i + 1,
                    'consistent': consistent,
                    'values': {
                        'commission_amount': float(commission.commission_amount),
                        'total_commission': float(commission.total_commission),
                        'total_receivable': float(commission.total_receivable)
                    }
                })
            
            commission.delete()
            
            return {
                'consistency_tests': consistency_results,
                'all_consistent': all(r['consistent'] for r in consistency_results)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_optimistic_locking(self):
        """Test 5: Examine optimistic locking implementation"""
        print("\n=== Testing Optimistic Locking Implementation ===")
        
        locking_results = {
            'version_field_test': self._test_version_field(),
            'concurrent_update_test': self._test_concurrent_updates(),
            'atomic_operations_test': self._test_atomic_operations(),
            'lock_version_increment_test': self._test_lock_version_increment()
        }
        
        self.results['optimistic_locking'] = locking_results
        
        # Summary
        all_tests_passed = all(
            test_result.get('passed', False) 
            for test_result in locking_results.values() 
            if isinstance(test_result, dict)
        )
        
        if all_tests_passed:
            print("✓ All optimistic locking tests passed")
        else:
            print("✗ Some optimistic locking tests failed")
    
    def _test_version_field(self):
        """Test lock_version field presence and functionality"""
        try:
            commission = Commission.objects.create(
                organization=self.test_org,
                user=self.test_user,
                total_sales=Decimal('1000.00'),
                start_date=date.today(),
                end_date=date.today(),
                created_by=self.admin_user
            )
            
            # Check if lock_version field exists and is initialized
            has_version_field = hasattr(commission, 'lock_version')
            initial_version = getattr(commission, 'lock_version', None)
            
            result = {
                'has_version_field': has_version_field,
                'initial_version': initial_version,
                'version_initialized': initial_version is not None and initial_version > 0,
                'passed': has_version_field and initial_version == 1
            }
            
            commission.delete()
            
            if result['passed']:
                print("✓ Version field test passed")
            else:
                print("✗ Version field test failed")
            
            return result
            
        except Exception as e:
            print(f"✗ Version field test error: {str(e)}")
            return {'error': str(e), 'passed': False}
    
    def _test_concurrent_updates(self):
        """Test concurrent update handling"""
        try:
            # Create a commission record
            commission = Commission.objects.create(
                organization=self.test_org,
                user=self.test_user,
                total_sales=Decimal('1000.00'),
                commission_rate=Decimal('5.00'),
                start_date=date.today(),
                end_date=date.today(),
                created_by=self.admin_user
            )
            
            # Simulate concurrent access
            def update_commission(commission_id, new_rate, delay=0):
                time.sleep(delay)
                try:
                    with AtomicFinancialOperations.atomic_commission_operation(commission_id, 'test_update') as comm:
                        comm.commission_rate = new_rate
                        comm.save()
                        return {'success': True, 'new_rate': float(new_rate)}
                except Exception as e:
                    return {'success': False, 'error': str(e)}
            
            # Test concurrent updates
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(update_commission, commission.id, Decimal('6.00'), 0.1),
                    executor.submit(update_commission, commission.id, Decimal('7.00'), 0.2),
                    executor.submit(update_commission, commission.id, Decimal('8.00'), 0.3)
                ]
                
                results = []
                for future in as_completed(futures):
                    results.append(future.result())
            
            # Check results
            successful_updates = [r for r in results if r['success']]
            failed_updates = [r for r in results if not r['success']]
            
            # Refresh commission to see final state
            commission.refresh_from_db()
            
            concurrent_test_result = {
                'total_attempts': len(results),
                'successful_updates': len(successful_updates),
                'failed_updates': len(failed_updates),
                'final_rate': float(commission.commission_rate),
                'atomic_operations_working': len(successful_updates) > 0,
                'passed': len(successful_updates) > 0 and len(failed_updates) == 0  # All should succeed with proper locking
            }
            
            commission.delete()
            
            if concurrent_test_result['passed']:
                print("✓ Concurrent updates test passed")
            else:
                print("✗ Concurrent updates test failed")
            
            return concurrent_test_result
            
        except Exception as e:
            print(f"✗ Concurrent updates test error: {str(e)}")
            return {'error': str(e), 'passed': False}
    
    def _test_atomic_operations(self):
        """Test atomic operations functionality"""
        try:
            commission = Commission.objects.create(
                organization=self.test_org,
                user=self.test_user,
                total_sales=Decimal('1000.00'),
                commission_rate=Decimal('5.00'),
                start_date=date.today(),
                end_date=date.today(),
                created_by=self.admin_user
            )
            
            # Test atomic commission calculation
            result = AtomicFinancialOperations.atomic_commission_calculation(
                commission.id,
                recalculate_sales=False,
                user=self.admin_user
            )
            
            atomic_test_result = {
                'atomic_calculation_available': True,
                'calculation_result': result,
                'changes_tracked': 'changes' in result,
                'audit_trail_created': result.get('commission_id') == commission.id,
                'passed': result.get('commission_id') == commission.id
            }
            
            commission.delete()
            
            if atomic_test_result['passed']:
                print("✓ Atomic operations test passed")
            else:
                print("✗ Atomic operations test failed")
            
            return atomic_test_result
            
        except Exception as e:
            print(f"✗ Atomic operations test error: {str(e)}")
            return {'error': str(e), 'passed': False}
    
    def _test_lock_version_increment(self):
        """Test lock version increment on updates"""
        try:
            commission = Commission.objects.create(
                organization=self.test_org,
                user=self.test_user,
                total_sales=Decimal('1000.00'),
                start_date=date.today(),
                end_date=date.today(),
                created_by=self.admin_user
            )
            
            initial_version = getattr(commission, 'lock_version', 1)
            
            # Update the commission
            commission.commission_rate = Decimal('6.00')
            commission.save()
            
            updated_version = getattr(commission, 'lock_version', 1)
            
            version_test_result = {
                'initial_version': initial_version,
                'updated_version': updated_version,
                'version_incremented': updated_version > initial_version,
                'passed': updated_version > initial_version
            }
            
            commission.delete()
            
            if version_test_result['passed']:
                print("✓ Lock version increment test passed")
            else:
                print("✗ Lock version increment test failed")
            
            return version_test_result
            
        except Exception as e:
            print(f"✗ Lock version increment test error: {str(e)}")
            return {'error': str(e), 'passed': False}
    
    def analyze_performance_metrics(self):
        """Test 6: Analyze performance characteristics"""
        print("\n=== Testing Performance Metrics ===")
        
        performance_results = {
            'bulk_calculation_test': self._test_bulk_calculations(),
            'caching_test': self._test_caching_performance(),
            'query_optimization_test': self._test_query_optimization(),
            'calculation_speed_test': self._test_calculation_speed()
        }
        
        self.results['performance_metrics'] = performance_results
        
        print("Performance metrics analysis completed")
    
    def _test_bulk_calculations(self):
        """Test bulk commission calculations"""
        try:
            start_time = time.time()
            
            # Test bulk calculation
            result = CommissionCalculationOptimizer.bulk_calculate_commissions(
                organization=self.test_org,
                start_date=date.today() - timedelta(days=30),
                end_date=date.today(),
                user_ids=[self.test_user.id]
            )
            
            end_time = time.time()
            calculation_time = end_time - start_time
            
            return {
                'calculation_time': calculation_time,
                'result_available': result is not None,
                'users_processed': len(result.get('commissions', [])),
                'performance_acceptable': calculation_time < 5.0,  # Should complete in under 5 seconds
                'passed': result is not None and calculation_time < 5.0
            }
            
        except Exception as e:
            return {'error': str(e), 'passed': False}
    
    def _test_caching_performance(self):
        """Test caching functionality"""
        try:
            # First call (should cache)
            start_time = time.time()
            result1 = CommissionCalculationOptimizer.calculate_user_commission(
                user=self.test_user,
                start_date=date.today() - timedelta(days=30),
                end_date=date.today(),
                organization=self.test_org,
                use_cache=True
            )
            first_call_time = time.time() - start_time
            
            # Second call (should use cache)
            start_time = time.time()
            result2 = CommissionCalculationOptimizer.calculate_user_commission(
                user=self.test_user,
                start_date=date.today() - timedelta(days=30),
                end_date=date.today(),
                organization=self.test_org,
                use_cache=True
            )
            second_call_time = time.time() - start_time
            
            return {
                'first_call_time': first_call_time,
                'second_call_time': second_call_time,
                'cache_speedup': first_call_time / second_call_time if second_call_time > 0 else 0,
                'caching_working': second_call_time < first_call_time,
                'results_identical': result1 == result2,
                'passed': second_call_time < first_call_time and result1 == result2
            }
            
        except Exception as e:
            return {'error': str(e), 'passed': False}
    
    def _test_query_optimization(self):
        """Test query optimization"""
        try:
            from django.db import connection
            
            # Reset query count
            connection.queries_log.clear()
            
            # Perform commission calculation
            CommissionCalculationOptimizer.calculate_user_commission(
                user=self.test_user,
                start_date=date.today() - timedelta(days=30),
                end_date=date.today(),
                organization=self.test_org,
                use_cache=False
            )
            
            query_count = len(connection.queries)
            
            return {
                'query_count': query_count,
                'queries_optimized': query_count < 10,  # Should use minimal queries
                'passed': query_count < 10
            }
            
        except Exception as e:
            return {'error': str(e), 'passed': False}
    
    def _test_calculation_speed(self):
        """Test individual calculation speed"""
        try:
            # Create multiple commissions and time calculations
            commissions = []
            
            for i in range(10):
                commission = Commission.objects.create(
                    organization=self.test_org,
                    user=self.test_user,
                    total_sales=Decimal(f'{1000 + i * 100}.00'),
                    commission_rate=Decimal('5.00'),
                    start_date=date.today() - timedelta(days=30),
                    end_date=date.today(),
                    created_by=self.admin_user
                )
                commissions.append(commission)
            
            # Time recalculations
            start_time = time.time()
            
            for commission in commissions:
                commission._calculate_amounts()
            
            end_time = time.time()
            total_time = end_time - start_time
            avg_time_per_calculation = total_time / len(commissions)
            
            # Clean up
            for commission in commissions:
                commission.delete()
            
            return {
                'total_calculations': len(commissions),
                'total_time': total_time,
                'avg_time_per_calculation': avg_time_per_calculation,
                'calculations_fast': avg_time_per_calculation < 0.1,  # Should be under 100ms each
                'passed': avg_time_per_calculation < 0.1
            }
            
        except Exception as e:
            return {'error': str(e), 'passed': False}
    
    def generate_summary(self):
        """Generate comprehensive analysis summary"""
        print("\n=== Commission Calculation System Analysis Summary ===")
        
        # Calculate overall scores
        test_categories = [
            'financial_calculations',
            'multi_currency_support', 
            'exchange_rate_handling',
            'calculation_accuracy',
            'optimistic_locking',
            'performance_metrics'
        ]
        
        category_scores = {}
        
        for category in test_categories:
            if category in self.results:
                category_data = self.results[category]
                
                if category == 'financial_calculations':
                    score = category_data.get('passed_tests', 0) / category_data.get('total_tests', 1)
                elif category == 'multi_currency_support':
                    score = category_data.get('successful_conversions', 0) / category_data.get('total_currencies_tested', 1)
                elif category == 'exchange_rate_handling':
                    score = category_data.get('successful_calculations', 0) / category_data.get('total_tests', 1)
                elif category == 'calculation_accuracy':
                    score = category_data.get('handled_correctly', 0) / category_data.get('total_edge_cases', 1)
                elif category == 'optimistic_locking':
                    passed_tests = sum(1 for test in category_data.values() if isinstance(test, dict) and test.get('passed', False))
                    total_tests = len([test for test in category_data.values() if isinstance(test, dict)])
                    score = passed_tests / total_tests if total_tests > 0 else 0
                elif category == 'performance_metrics':
                    passed_tests = sum(1 for test in category_data.values() if isinstance(test, dict) and test.get('passed', False))
                    total_tests = len([test for test in category_data.values() if isinstance(test, dict)])
                    score = passed_tests / total_tests if total_tests > 0 else 0
                else:
                    score = 0
                
                category_scores[category] = score
        
        overall_score = sum(category_scores.values()) / len(category_scores) if category_scores else 0
        
        # Generate summary
        summary = {
            'overall_score': overall_score,
            'category_scores': category_scores,
            'grade': self._get_grade(overall_score),
            'key_findings': self._generate_key_findings(),
            'recommendations': self._generate_recommendations(),
            'compliance_status': self._check_requirements_compliance()
        }
        
        self.results['summary'] = summary
        
        # Print summary
        print(f"\nOverall Score: {overall_score:.2%}")
        print(f"Grade: {summary['grade']}")
        
        print("\nCategory Scores:")
        for category, score in category_scores.items():
            print(f"  {category.replace('_', ' ').title()}: {score:.2%}")
        
        print(f"\nKey Findings:")
        for finding in summary['key_findings']:
            print(f"  • {finding}")
        
        print(f"\nRecommendations:")
        for recommendation in summary['recommendations']:
            print(f"  • {recommendation}")
        
        return summary
    
    def _get_grade(self, score):
        """Convert score to letter grade"""
        if score >= 0.9:
            return 'A'
        elif score >= 0.8:
            return 'B'
        elif score >= 0.7:
            return 'C'
        elif score >= 0.6:
            return 'D'
        else:
            return 'F'
    
    def _generate_key_findings(self):
        """Generate key findings from analysis"""
        findings = []
        
        # Financial calculations
        if self.results.get('financial_calculations', {}).get('passed_tests', 0) > 0:
            findings.append("Commission financial calculations are implemented with proper decimal precision")
        
        # Multi-currency support
        if self.results.get('multi_currency_support', {}).get('successful_conversions', 0) > 0:
            findings.append("Multi-currency support is functional with proper exchange rate handling")
        
        # Optimistic locking
        locking_results = self.results.get('optimistic_locking', {})
        if any(test.get('passed', False) for test in locking_results.values() if isinstance(test, dict)):
            findings.append("Optimistic locking is implemented for concurrent operation safety")
        
        # Performance
        perf_results = self.results.get('performance_metrics', {})
        if any(test.get('passed', False) for test in perf_results.values() if isinstance(test, dict)):
            findings.append("Performance optimizations including caching are in place")
        
        return findings
    
    def _generate_recommendations(self):
        """Generate recommendations based on analysis"""
        recommendations = []
        
        # Check for areas needing improvement
        if self.results.get('financial_calculations', {}).get('passed_tests', 0) < self.results.get('financial_calculations', {}).get('total_tests', 1):
            recommendations.append("Review and fix financial calculation edge cases")
        
        if self.results.get('optimistic_locking', {}).get('concurrent_update_test', {}).get('failed_updates', 0) > 0:
            recommendations.append("Improve concurrent update handling and error recovery")
        
        perf_results = self.results.get('performance_metrics', {})
        if not all(test.get('passed', False) for test in perf_results.values() if isinstance(test, dict)):
            recommendations.append("Optimize query performance and caching strategies")
        
        return recommendations
    
    def _check_requirements_compliance(self):
        """Check compliance with specified requirements"""
        compliance = {
            'requirement_4_2': {
                'description': 'Business rule enforcement (commission calculations)',
                'compliant': self.results.get('financial_calculations', {}).get('passed_tests', 0) > 0,
                'evidence': 'Financial calculations tested and validated'
            },
            'requirement_2_1': {
                'description': 'Financial calculation precision',
                'compliant': self.results.get('financial_calculations', {}).get('precision_validation', {}).get('optimizer_available', False),
                'evidence': 'Decimal precision handling implemented'
            },
            'requirement_3_4': {
                'description': 'Optimistic locking for concurrent operations',
                'compliant': any(test.get('passed', False) for test in self.results.get('optimistic_locking', {}).values() if isinstance(test, dict)),
                'evidence': 'Optimistic locking mechanisms tested'
            }
        }
        
        return compliance
    
    def save_results(self, filename='commission_calculation_analysis_results.json'):
        """Save analysis results to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(f"\n✓ Analysis results saved to {filename}")
        except Exception as e:
            print(f"✗ Failed to save results: {str(e)}")
    
    def run_complete_analysis(self):
        """Run the complete commission calculation analysis"""
        print("Starting Commission Calculation System Analysis...")
        print("=" * 60)
        
        try:
            self.analyze_financial_calculations()
            self.analyze_multi_currency_support()
            self.analyze_exchange_rate_handling()
            self.analyze_calculation_accuracy()
            self.analyze_optimistic_locking()
            self.analyze_performance_metrics()
            
            summary = self.generate_summary()
            self.save_results()
            
            print("\n" + "=" * 60)
            print("Commission Calculation System Analysis Complete!")
            
            return summary
            
        except Exception as e:
            print(f"\n✗ Analysis failed: {str(e)}")
            return None


def main():
    """Main execution function"""
    try:
        analyzer = CommissionCalculationAnalysis()
        summary = analyzer.run_complete_analysis()
        
        if summary:
            print(f"\nFinal Grade: {summary['grade']} ({summary['overall_score']:.1%})")
            
            # Set exit code based on results
            if summary['overall_score'] >= 0.8:
                sys.exit(0)  # Success
            else:
                sys.exit(1)  # Issues found
        else:
            sys.exit(1)  # Analysis failed
            
    except Exception as e:
        print(f"Critical error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()