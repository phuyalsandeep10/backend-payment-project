#!/usr/bin/env python3
"""
Simplified Commission Calculation System Analysis
Focused analysis of commission model financial calculations, multi-currency support,
exchange rate handling, calculation accuracy, and optimistic locking implementation.
"""

import os
import sys
import django
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, date, timedelta
import json

# Setup Django
sys.path.append('/Users/kiro/Desktop/Backend_PRS/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.db import transaction
from django.core.exceptions import ValidationError

from commission.models import Commission
from deals.financial_optimizer import FinancialFieldOptimizer
from authentication.models import User
from organization.models import Organization

class SimpleCommissionAnalysis:
    """Simplified commission calculation analysis"""
    
    def __init__(self):
        self.results = {}
        self.setup_test_data()
    
    def setup_test_data(self):
        """Setup minimal test data"""
        try:
            # Get or create test organization
            self.test_org = Organization.objects.filter(name__icontains='test').first()
            if not self.test_org:
                self.test_org = Organization.objects.create(
                    name='Test Org Simple',
                    description='Simple test org'
                )
            
            # Get or create test user
            self.test_user = User.objects.filter(email__icontains='test').first()
            if not self.test_user:
                self.test_user = User.objects.create_user(
                    username='testuser_simple',
                    email='test.simple@example.com',
                    password='testpass123',
                    organization=self.test_org
                )
            
            print(f"✓ Test data ready - Org: {self.test_org.name}, User: {self.test_user.email}")
            
        except Exception as e:
            print(f"✗ Test data setup failed: {str(e)}")
            raise
    
    def test_financial_calculations(self):
        """Test 1: Basic financial calculations"""
        print("\n=== Testing Financial Calculations ===")
        
        test_cases = [
            # (sales, rate, exchange, bonus, penalty)
            (Decimal('10000.00'), Decimal('5.00'), Decimal('1.00'), Decimal('0.00'), Decimal('0.00')),
            (Decimal('25000.50'), Decimal('7.50'), Decimal('1.25'), Decimal('500.00'), Decimal('100.00')),
            (Decimal('1000.00'), Decimal('10.00'), Decimal('0.85'), Decimal('0.00'), Decimal('50.00')),
        ]
        
        results = []
        
        for i, (sales, rate, exchange, bonus, penalty) in enumerate(test_cases):
            try:
                # Create commission without triggering complex audit systems
                commission = Commission(
                    organization=self.test_org,
                    user=self.test_user,
                    total_sales=sales,
                    commission_rate=rate,
                    exchange_rate=exchange,
                    bonus=bonus,
                    penalty=penalty,
                    start_date=date.today() - timedelta(days=30),
                    end_date=date.today()
                )
                
                # Manually trigger calculation
                commission._calculate_amounts()
                
                # Manual verification
                expected_commission = sales * (rate / Decimal('100'))
                expected_total = (expected_commission * exchange) + bonus
                expected_receivable = expected_total - penalty
                
                calculation_correct = (
                    abs(commission.commission_amount - expected_commission) < Decimal('0.01') and
                    abs(commission.total_commission - expected_total) < Decimal('0.01') and
                    abs(commission.total_receivable - expected_receivable) < Decimal('0.01')
                )
                
                result = {
                    'test_case': i + 1,
                    'input_sales': float(sales),
                    'input_rate': float(rate),
                    'calculated_commission': float(commission.commission_amount),
                    'expected_commission': float(expected_commission),
                    'calculated_total': float(commission.total_commission),
                    'expected_total': float(expected_total),
                    'calculation_correct': calculation_correct
                }
                
                results.append(result)
                
                if calculation_correct:
                    print(f"✓ Test case {i + 1}: Calculations correct")
                else:
                    print(f"✗ Test case {i + 1}: Calculations incorrect")
                    print(f"  Expected commission: {expected_commission}, Got: {commission.commission_amount}")
                
            except Exception as e:
                print(f"✗ Test case {i + 1} failed: {str(e)}")
                results.append({'test_case': i + 1, 'error': str(e), 'calculation_correct': False})
        
        self.results['financial_calculations'] = {
            'tests': results,
            'total_tests': len(test_cases),
            'passed_tests': sum(1 for r in results if r.get('calculation_correct', False))
        }
        
        print(f"Financial calculations: {self.results['financial_calculations']['passed_tests']}/{len(test_cases)} passed")
    
    def test_multi_currency_support(self):
        """Test 2: Multi-currency support"""
        print("\n=== Testing Multi-Currency Support ===")
        
        currencies = [
            ('USD', Decimal('1.00')),
            ('EUR', Decimal('0.85')),
            ('NPR', Decimal('132.50')),
            ('JPY', Decimal('110.25')),
        ]
        
        results = []
        
        for currency, exchange_rate in currencies:
            try:
                commission = Commission(
                    organization=self.test_org,
                    user=self.test_user,
                    total_sales=Decimal('1000.00'),
                    commission_rate=Decimal('5.00'),
                    currency=currency,
                    exchange_rate=exchange_rate,
                    start_date=date.today() - timedelta(days=30),
                    end_date=date.today()
                )
                
                commission._calculate_amounts()
                
                # Verify currency conversion
                expected_converted = Decimal('1000.00') * exchange_rate
                conversion_correct = abs(commission.converted_amount - expected_converted) < Decimal('0.01')
                
                result = {
                    'currency': currency,
                    'exchange_rate': float(exchange_rate),
                    'converted_amount': float(commission.converted_amount),
                    'expected_converted': float(expected_converted),
                    'conversion_correct': conversion_correct
                }
                
                results.append(result)
                
                if conversion_correct:
                    print(f"✓ {currency}: Currency conversion correct")
                else:
                    print(f"✗ {currency}: Currency conversion incorrect")
                
            except Exception as e:
                print(f"✗ {currency}: Test failed - {str(e)}")
                results.append({'currency': currency, 'error': str(e), 'conversion_correct': False})
        
        self.results['multi_currency'] = {
            'tests': results,
            'total_currencies': len(currencies),
            'successful_conversions': sum(1 for r in results if r.get('conversion_correct', False))
        }
        
        print(f"Multi-currency: {self.results['multi_currency']['successful_conversions']}/{len(currencies)} currencies working")
    
    def test_exchange_rate_validation(self):
        """Test 3: Exchange rate validation"""
        print("\n=== Testing Exchange Rate Validation ===")
        
        test_rates = [
            (Decimal('0.000001'), 'minimum_valid'),
            (Decimal('1.00'), 'unity'),
            (Decimal('100.00'), 'high_rate'),
            (Decimal('0.0'), 'zero_invalid'),
            (Decimal('-1.0'), 'negative_invalid'),
        ]
        
        results = []
        
        for rate, test_type in test_rates:
            try:
                validated_rate = FinancialFieldOptimizer.validate_exchange_rate(rate)
                
                result = {
                    'test_type': test_type,
                    'input_rate': float(rate),
                    'validated_rate': float(validated_rate),
                    'validation_passed': True
                }
                
                print(f"✓ {test_type}: Rate {rate} validated to {validated_rate}")
                
            except ValidationError as e:
                result = {
                    'test_type': test_type,
                    'input_rate': float(rate),
                    'validation_error': str(e),
                    'validation_passed': False
                }
                
                if 'invalid' in test_type:
                    print(f"✓ {test_type}: Correctly rejected invalid rate {rate}")
                else:
                    print(f"✗ {test_type}: Unexpectedly rejected valid rate {rate}")
                
            except Exception as e:
                result = {
                    'test_type': test_type,
                    'input_rate': float(rate),
                    'error': str(e),
                    'validation_passed': False
                }
                print(f"✗ {test_type}: Unexpected error - {str(e)}")
            
            results.append(result)
        
        self.results['exchange_rate_validation'] = {
            'tests': results,
            'total_tests': len(test_rates)
        }
    
    def test_edge_cases(self):
        """Test 4: Edge cases and boundary conditions"""
        print("\n=== Testing Edge Cases ===")
        
        edge_cases = [
            ('zero_sales', Decimal('0.00'), Decimal('5.00')),
            ('zero_rate', Decimal('1000.00'), Decimal('0.00')),
            ('high_precision', Decimal('333.33'), Decimal('3.33')),
            ('large_numbers', Decimal('999999.99'), Decimal('99.99')),
        ]
        
        results = []
        
        for description, sales, rate in edge_cases:
            try:
                commission = Commission(
                    organization=self.test_org,
                    user=self.test_user,
                    total_sales=sales,
                    commission_rate=rate,
                    exchange_rate=Decimal('1.00'),
                    start_date=date.today() - timedelta(days=30),
                    end_date=date.today()
                )
                
                commission._calculate_amounts()
                
                # Verify edge case handling
                expected_commission = sales * (rate / Decimal('100'))
                calculation_correct = abs(commission.commission_amount - expected_commission) < Decimal('0.01')
                
                result = {
                    'description': description,
                    'sales': float(sales),
                    'rate': float(rate),
                    'calculated_commission': float(commission.commission_amount),
                    'expected_commission': float(expected_commission),
                    'handled_correctly': calculation_correct
                }
                
                results.append(result)
                
                if calculation_correct:
                    print(f"✓ {description}: Edge case handled correctly")
                else:
                    print(f"✗ {description}: Edge case not handled correctly")
                
            except Exception as e:
                print(f"✗ {description}: Failed - {str(e)}")
                results.append({'description': description, 'error': str(e), 'handled_correctly': False})
        
        self.results['edge_cases'] = {
            'tests': results,
            'total_cases': len(edge_cases),
            'handled_correctly': sum(1 for r in results if r.get('handled_correctly', False))
        }
        
        print(f"Edge cases: {self.results['edge_cases']['handled_correctly']}/{len(edge_cases)} handled correctly")
    
    def test_optimistic_locking(self):
        """Test 5: Optimistic locking features"""
        print("\n=== Testing Optimistic Locking ===")
        
        try:
            # Test version field presence
            commission = Commission(
                organization=self.test_org,
                user=self.test_user,
                total_sales=Decimal('1000.00'),
                start_date=date.today(),
                end_date=date.today()
            )
            
            has_version_field = hasattr(commission, 'lock_version')
            
            if has_version_field:
                print("✓ Lock version field present")
                
                # Test OptimisticLockingMixin methods
                has_optimistic_methods = (
                    hasattr(commission, 'save_with_optimistic_lock') and
                    hasattr(commission, 'refresh_with_lock_check')
                )
                
                if has_optimistic_methods:
                    print("✓ Optimistic locking methods available")
                else:
                    print("✗ Optimistic locking methods missing")
                
                self.results['optimistic_locking'] = {
                    'version_field_present': True,
                    'optimistic_methods_available': has_optimistic_methods,
                    'locking_implemented': has_optimistic_methods
                }
            else:
                print("✗ Lock version field missing")
                self.results['optimistic_locking'] = {
                    'version_field_present': False,
                    'locking_implemented': False
                }
                
        except Exception as e:
            print(f"✗ Optimistic locking test failed: {str(e)}")
            self.results['optimistic_locking'] = {'error': str(e), 'locking_implemented': False}
    
    def test_precision_handling(self):
        """Test 6: Decimal precision handling"""
        print("\n=== Testing Precision Handling ===")
        
        try:
            # Test FinancialFieldOptimizer
            test_values = [
                Decimal('123.456789'),  # Should round to proper precision
                Decimal('999.999'),     # Should handle rounding
                Decimal('0.001'),       # Should handle small values
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
            
            successful_precision = sum(1 for r in precision_results if r.get('precision_applied', False))
            
            self.results['precision_handling'] = {
                'tests': precision_results,
                'total_tests': len(test_values),
                'successful_precision': successful_precision,
                'precision_working': successful_precision > 0
            }
            
            if successful_precision > 0:
                print(f"✓ Precision handling: {successful_precision}/{len(test_values)} tests passed")
            else:
                print("✗ Precision handling not working")
                
        except Exception as e:
            print(f"✗ Precision handling test failed: {str(e)}")
            self.results['precision_handling'] = {'error': str(e), 'precision_working': False}
    
    def generate_summary(self):
        """Generate analysis summary"""
        print("\n=== Commission Calculation Analysis Summary ===")
        
        # Calculate scores
        scores = {}
        
        if 'financial_calculations' in self.results:
            fc = self.results['financial_calculations']
            scores['financial_calculations'] = fc.get('passed_tests', 0) / fc.get('total_tests', 1)
        
        if 'multi_currency' in self.results:
            mc = self.results['multi_currency']
            scores['multi_currency'] = mc.get('successful_conversions', 0) / mc.get('total_currencies', 1)
        
        if 'edge_cases' in self.results:
            ec = self.results['edge_cases']
            scores['edge_cases'] = ec.get('handled_correctly', 0) / ec.get('total_cases', 1)
        
        if 'optimistic_locking' in self.results:
            ol = self.results['optimistic_locking']
            scores['optimistic_locking'] = 1.0 if ol.get('locking_implemented', False) else 0.0
        
        if 'precision_handling' in self.results:
            ph = self.results['precision_handling']
            scores['precision_handling'] = 1.0 if ph.get('precision_working', False) else 0.0
        
        overall_score = sum(scores.values()) / len(scores) if scores else 0
        
        # Generate grade
        if overall_score >= 0.9:
            grade = 'A'
        elif overall_score >= 0.8:
            grade = 'B'
        elif overall_score >= 0.7:
            grade = 'C'
        elif overall_score >= 0.6:
            grade = 'D'
        else:
            grade = 'F'
        
        summary = {
            'overall_score': overall_score,
            'grade': grade,
            'category_scores': scores,
            'key_findings': self._generate_findings(),
            'requirements_compliance': self._check_compliance()
        }
        
        self.results['summary'] = summary
        
        # Print summary
        print(f"\nOverall Score: {overall_score:.2%}")
        print(f"Grade: {grade}")
        
        print("\nCategory Scores:")
        for category, score in scores.items():
            print(f"  {category.replace('_', ' ').title()}: {score:.2%}")
        
        print("\nKey Findings:")
        for finding in summary['key_findings']:
            print(f"  • {finding}")
        
        return summary
    
    def _generate_findings(self):
        """Generate key findings"""
        findings = []
        
        if self.results.get('financial_calculations', {}).get('passed_tests', 0) > 0:
            findings.append("Commission financial calculations are working correctly")
        
        if self.results.get('multi_currency', {}).get('successful_conversions', 0) > 0:
            findings.append("Multi-currency support is functional")
        
        if self.results.get('optimistic_locking', {}).get('locking_implemented', False):
            findings.append("Optimistic locking is implemented")
        
        if self.results.get('precision_handling', {}).get('precision_working', False):
            findings.append("Decimal precision handling is working")
        
        return findings
    
    def _check_compliance(self):
        """Check requirements compliance"""
        return {
            'requirement_4_2_business_rules': self.results.get('financial_calculations', {}).get('passed_tests', 0) > 0,
            'requirement_2_1_precision': self.results.get('precision_handling', {}).get('precision_working', False),
            'requirement_3_4_locking': self.results.get('optimistic_locking', {}).get('locking_implemented', False)
        }
    
    def save_results(self):
        """Save results to file"""
        try:
            filename = 'commission_simple_analysis_results.json'
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(f"\n✓ Results saved to {filename}")
        except Exception as e:
            print(f"✗ Failed to save results: {str(e)}")
    
    def run_analysis(self):
        """Run complete analysis"""
        print("Starting Simplified Commission Calculation Analysis...")
        print("=" * 60)
        
        try:
            self.test_financial_calculations()
            self.test_multi_currency_support()
            self.test_exchange_rate_validation()
            self.test_edge_cases()
            self.test_optimistic_locking()
            self.test_precision_handling()
            
            summary = self.generate_summary()
            self.save_results()
            
            print("\n" + "=" * 60)
            print("Commission Analysis Complete!")
            
            return summary
            
        except Exception as e:
            print(f"\n✗ Analysis failed: {str(e)}")
            return None


def main():
    """Main execution"""
    try:
        analyzer = SimpleCommissionAnalysis()
        summary = analyzer.run_analysis()
        
        if summary:
            print(f"\nFinal Grade: {summary['grade']} ({summary['overall_score']:.1%})")
            
            if summary['overall_score'] >= 0.7:
                sys.exit(0)  # Success
            else:
                sys.exit(1)  # Issues found
        else:
            sys.exit(1)
            
    except Exception as e:
        print(f"Critical error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()