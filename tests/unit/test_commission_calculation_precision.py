"""
Commission Calculation Precision Tests - Task 5.3.1

Test suite for commission calculation precision, exchange rate validation,
and comprehensive commission calculation accuracy.
"""

import unittest
from decimal import Decimal
from django.test import TestCase
from django.core.exceptions import ValidationError
from apps.deals.financial_optimizer import FinancialFieldOptimizer
from apps.commission.models import Commission
from apps.organization.models import Organization
from django.contrib.auth import get_user_model

User = get_user_model()


class TestCommissionCalculationPrecision(TestCase):
    """
    Test commission calculation precision validation
    Task 5.3.1: Commission calculation precision validation
    """
    
    def setUp(self):
        """Set up test data"""
        self.optimizer = FinancialFieldOptimizer()
    
    def test_basic_commission_calculation_precision(self):
        """Test basic commission calculation maintains exact precision"""
        
        # Test case: $1000 sales at 5% commission = $50.00
        result = self.optimizer.calculate_commission_amount(
            Decimal('1000.00'), Decimal('5.0000')
        )
        
        self.assertEqual(result, Decimal('50.00'))
        self.assertEqual(result.as_tuple().exponent, -2)  # Exactly 2 decimal places
    
    def test_commission_calculation_rounding(self):
        """Test commission calculation rounding behavior"""
        
        # Test case: $333.33 sales at 10% commission = $33.333 -> $33.33
        result = self.optimizer.calculate_commission_amount(
            Decimal('333.33'), Decimal('10.0000')
        )
        
        self.assertEqual(result, Decimal('33.33'))
        self.assertEqual(result.as_tuple().exponent, -2)
        
        # Test banker's rounding: $123.45 at 3.333% = $4.115 -> $4.12
        result = self.optimizer.calculate_commission_amount(
            Decimal('123.45'), Decimal('3.3330')
        )
        
        self.assertEqual(result, Decimal('4.11'))  # Rounds down from 4.115
    
    def test_high_precision_commission_rates(self):
        """Test commission calculations with high precision rates"""
        
        # Test 4 decimal place commission rate
        result = self.optimizer.calculate_commission_amount(
            Decimal('10000.00'), Decimal('2.5678')
        )
        
        self.assertEqual(result, Decimal('256.78'))
        self.assertEqual(result.as_tuple().exponent, -2)
        
        # Test very small commission rate
        result = self.optimizer.calculate_commission_amount(
            Decimal('50000.00'), Decimal('0.0001')
        )
        
        self.assertEqual(result, Decimal('0.05'))
    
    def test_commission_calculation_overflow_protection(self):
        """Test overflow protection in commission calculations"""
        
        # Test that extremely high sales amount with high commission rate fails
        with self.assertRaises(ValidationError) as context:
            self.optimizer.calculate_commission_amount(
                Decimal('999999999.99'), Decimal('50.0000')
            )
        
        self.assertIn('overflow', str(context.exception).lower())
    
    def test_currency_conversion_precision(self):
        """Test currency conversion maintains precision"""
        
        # USD to EUR conversion
        result = self.optimizer.calculate_currency_conversion(
            Decimal('1000.00'), Decimal('0.850000')
        )
        
        self.assertEqual(result, Decimal('850.00'))
        self.assertEqual(result.as_tuple().exponent, -2)
        
        # Test high precision exchange rate
        result = self.optimizer.calculate_currency_conversion(
            Decimal('1000.00'), Decimal('1.234567')
        )
        
        self.assertEqual(result, Decimal('1234.57'))  # Rounded to 2 decimal places
    
    def test_currency_conversion_overflow_protection(self):
        """Test overflow protection in currency conversion"""
        
        # Test conversion that would exceed maximum currency value
        with self.assertRaises(ValidationError) as context:
            self.optimizer.calculate_currency_conversion(
                Decimal('500000000.00'), Decimal('5.000000')
            )
        
        self.assertIn('overflow', str(context.exception).lower())
    
    def test_comprehensive_commission_calculation(self):
        """Test comprehensive commission calculation with all components"""
        
        # Test complete commission calculation scenario
        result = self.optimizer.calculate_comprehensive_commission(
            sales_amount=Decimal('10000.00'),
            commission_rate=Decimal('5.0000'),
            exchange_rate=Decimal('1.250000'),
            bonus=Decimal('100.00'),
            penalty=Decimal('25.00')
        )
        
        self.assertTrue(result['success'])
        
        # Verify calculation steps
        calculations = result['calculations']
        self.assertEqual(calculations['base_commission'], Decimal('500.00'))
        self.assertEqual(calculations['converted_commission'], Decimal('625.00'))
        self.assertEqual(calculations['commission_with_bonus'], Decimal('725.00'))
        self.assertEqual(calculations['final_commission'], Decimal('700.00'))
        
        # Verify precision of all calculated amounts
        for key, value in calculations.items():
            if isinstance(value, Decimal) and key != 'effective_commission_rate':
                self.assertEqual(value.as_tuple().exponent, -2, f'{key} does not have 2 decimal places')
    
    def test_negative_commission_scenarios(self):
        """Test scenarios where penalties result in negative commissions"""
        
        result = self.optimizer.calculate_comprehensive_commission(
            sales_amount=Decimal('1000.00'),
            commission_rate=Decimal('5.0000'),  # $50 commission
            penalty=Decimal('75.00')  # Penalty exceeds commission
        )
        
        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['final_commission'], Decimal('-25.00'))
        self.assertGreater(len(result['warnings']), 0)
        self.assertIn('negative', result['warnings'][0].lower())
    
    def test_commission_rate_edge_cases(self):
        """Test commission calculation with edge case rates"""
        
        # Zero commission rate
        result = self.optimizer.calculate_commission_amount(
            Decimal('1000.00'), Decimal('0.0000')
        )
        self.assertEqual(result, Decimal('0.00'))
        
        # Maximum commission rate (100%)
        result = self.optimizer.calculate_commission_amount(
            Decimal('1000.00'), Decimal('100.0000')
        )
        self.assertEqual(result, Decimal('1000.00'))
        
        # Very small commission rate
        result = self.optimizer.calculate_commission_amount(
            Decimal('10000.00'), Decimal('0.0010')
        )
        self.assertEqual(result, Decimal('0.10'))
    
    def test_effective_commission_rate_calculation(self):
        """Test effective commission rate calculation with bonuses/penalties"""
        
        result = self.optimizer.calculate_comprehensive_commission(
            sales_amount=Decimal('1000.00'),
            commission_rate=Decimal('10.0000'),  # Base 10%
            bonus=Decimal('50.00'),  # Additional $50
            penalty=Decimal('25.00')  # Penalty $25
        )
        
        # Base commission: $100, After bonus/penalty: $125
        # Effective rate: 12.5%
        expected_effective_rate = Decimal('12.5000')
        self.assertEqual(result['calculations']['effective_commission_rate'], expected_effective_rate)


class TestCommissionCalculationAccuracy(TestCase):
    """
    Test commission calculation accuracy with predefined test cases
    Task 5.3.1: Commission calculation accuracy tests
    """
    
    def setUp(self):
        """Set up test data"""
        self.optimizer = FinancialFieldOptimizer()
    
    def test_accuracy_with_known_test_cases(self):
        """Test calculation accuracy with known correct results"""
        
        test_cases = [
            {
                'sales_amount': Decimal('1000.00'),
                'commission_rate': Decimal('5.0000'),
                'expected_result': Decimal('50.00')
            },
            {
                'sales_amount': Decimal('2500.00'),
                'commission_rate': Decimal('7.5000'),
                'expected_result': Decimal('187.50')
            },
            {
                'sales_amount': Decimal('999.99'),
                'commission_rate': Decimal('10.0000'),
                'expected_result': Decimal('100.00')  # Rounded up
            },
            {
                'sales_amount': Decimal('12345.67'),
                'commission_rate': Decimal('3.2500'),
                'expected_result': Decimal('401.23')
            },
            {
                'sales_amount': Decimal('50000.00'),
                'commission_rate': Decimal('2.7500'),
                'expected_result': Decimal('1375.00')
            }
        ]
        
        accuracy_result = self.optimizer.validate_commission_calculation_accuracy(test_cases)
        
        # All basic test cases should pass
        self.assertEqual(accuracy_result['failed_tests'], 0)
        self.assertEqual(accuracy_result['passed_tests'], len(test_cases))
        self.assertTrue(accuracy_result['summary']['all_tests_passed'])
        self.assertGreaterEqual(accuracy_result['accuracy_rate'], Decimal('100.00'))
    
    def test_accuracy_with_complex_scenarios(self):
        """Test accuracy with complex commission scenarios including conversions"""
        
        test_cases = [
            {
                'sales_amount': Decimal('10000.00'),
                'commission_rate': Decimal('5.0000'),
                'exchange_rate': Decimal('1.250000'),
                'bonus': Decimal('100.00'),
                'penalty': Decimal('50.00'),
                'expected_result': Decimal('675.00')  # (10000 * 0.05 * 1.25) + 100 - 50
            },
            {
                'sales_amount': Decimal('5000.00'),
                'commission_rate': Decimal('8.7500'),
                'exchange_rate': Decimal('0.850000'),
                'bonus': Decimal('0.00'),
                'penalty': Decimal('0.00'),
                'expected_result': Decimal('371.25')  # 5000 * 0.0875 * 0.85
            },
            {
                'sales_amount': Decimal('25000.00'),
                'commission_rate': Decimal('3.0000'),
                'exchange_rate': Decimal('1.000000'),
                'bonus': Decimal('200.00'),
                'penalty': Decimal('150.00'),
                'expected_result': Decimal('800.00')  # (25000 * 0.03) + 200 - 150
            }
        ]
        
        accuracy_result = self.optimizer.validate_commission_calculation_accuracy(test_cases)
        
        # Complex scenarios should also pass
        self.assertGreaterEqual(accuracy_result['accuracy_rate'], Decimal('95.00'))
        self.assertTrue(accuracy_result['summary']['precision_consistent'])
    
    def test_accuracy_with_edge_cases(self):
        """Test accuracy with edge case scenarios"""
        
        edge_cases = [
            {
                'sales_amount': Decimal('0.01'),  # Minimum sales
                'commission_rate': Decimal('1.0000'),
                'expected_result': Decimal('0.00')  # Should round to 0
            },
            {
                'sales_amount': Decimal('999999.99'),  # High sales amount
                'commission_rate': Decimal('0.0100'),  # Very low commission
                'expected_result': Decimal('100.00')
            },
            {
                'sales_amount': Decimal('1000.00'),
                'commission_rate': Decimal('0.0000'),  # Zero commission
                'expected_result': Decimal('0.00')
            }
        ]
        
        accuracy_result = self.optimizer.validate_commission_calculation_accuracy(edge_cases)
        
        # Edge cases should handle gracefully
        self.assertEqual(accuracy_result['failed_tests'], 0)
        self.assertTrue(accuracy_result['summary']['all_tests_passed'])
    
    def test_precision_consistency_across_calculations(self):
        """Test that precision is consistent across different calculation paths"""
        
        # Test multiple ways to achieve same result
        sales_amount = Decimal('2000.00')
        rate = Decimal('5.0000')
        
        # Method 1: Direct calculation
        direct_result = self.optimizer.calculate_commission_amount(sales_amount, rate)
        
        # Method 2: Through comprehensive calculation
        comprehensive_result = self.optimizer.calculate_comprehensive_commission(
            sales_amount, rate
        )
        
        # Method 3: Manual calculation for comparison
        manual_result = (sales_amount * rate / 100).quantize(
            self.optimizer.CURRENCY_PRECISION, rounding='ROUND_HALF_UP'
        )
        
        # All methods should produce identical results
        self.assertEqual(direct_result, comprehensive_result['summary']['final_commission'])
        self.assertEqual(direct_result, manual_result)
        
        # All should have exactly 2 decimal places
        self.assertEqual(direct_result.as_tuple().exponent, -2)
        self.assertEqual(comprehensive_result['summary']['final_commission'].as_tuple().exponent, -2)


class TestExchangeRateValidation(TestCase):
    """
    Test exchange rate validation enhancements for commission calculations
    Task 5.3.1: Exchange rate validation for commissions
    """
    
    def setUp(self):
        """Set up test data"""
        self.optimizer = FinancialFieldOptimizer()
    
    def test_exchange_rate_precision_validation(self):
        """Test exchange rate precision validation"""
        
        # Valid exchange rates with proper precision
        valid_rates = [
            Decimal('1.000000'),
            Decimal('0.850000'),
            Decimal('1.234567'),
            Decimal('0.000001')  # Minimum allowed
        ]
        
        for rate in valid_rates:
            validated = self.optimizer.validate_exchange_rate(rate)
            self.assertEqual(validated.as_tuple().exponent, -6)
        
        # Invalid exchange rates (too many decimal places)
        with self.assertRaises(ValidationError):
            self.optimizer.validate_exchange_rate(Decimal('1.0000001'))
    
    def test_exchange_rate_overflow_protection(self):
        """Test exchange rate overflow protection"""
        
        # Rate too high
        with self.assertRaises(ValidationError) as context:
            self.optimizer.validate_exchange_rate(Decimal('50000.000000'))
        
        self.assertIn('overflow protection', str(context.exception))
        
        # Rate too low
        with self.assertRaises(ValidationError) as context:
            self.optimizer.validate_exchange_rate(Decimal('0.0000001'))
        
        self.assertIn('overflow protection', str(context.exception))
    
    def test_commission_with_extreme_exchange_rates(self):
        """Test commission calculations with extreme but valid exchange rates"""
        
        # Very high exchange rate
        result = self.optimizer.calculate_comprehensive_commission(
            sales_amount=Decimal('1000.00'),
            commission_rate=Decimal('5.0000'),
            exchange_rate=Decimal('100.000000')
        )
        
        self.assertTrue(result['success'])
        self.assertEqual(result['calculations']['base_commission'], Decimal('50.00'))
        self.assertEqual(result['calculations']['converted_commission'], Decimal('5000.00'))
        
        # Very low exchange rate
        result = self.optimizer.calculate_comprehensive_commission(
            sales_amount=Decimal('10000.00'),
            commission_rate=Decimal('10.0000'),
            exchange_rate=Decimal('0.001000')
        )
        
        self.assertTrue(result['success'])
        self.assertEqual(result['calculations']['base_commission'], Decimal('1000.00'))
        self.assertEqual(result['calculations']['converted_commission'], Decimal('1.00'))
    
    def test_exchange_rate_string_conversion(self):
        """Test that exchange rates can be provided as strings and converted properly"""
        
        # Test string input conversion
        result = self.optimizer.calculate_currency_conversion(
            Decimal('1000.00'), '1.250000'
        )
        
        self.assertEqual(result, Decimal('1250.00'))
        
        # Test scientific notation
        result = self.optimizer.calculate_currency_conversion(
            Decimal('1000.00'), '1.25E+0'
        )
        
        self.assertEqual(result, Decimal('1250.00'))


class TestCommissionModelIntegration(TestCase):
    """
    Test integration of enhanced commission calculations with Django models
    Task 5.3.1: Model integration testing
    """
    
    def setUp(self):
        """Set up test models"""
        self.organization = Organization.objects.create(
            name="Commission Test Org",
            is_active=True
        )
        
        self.user = User.objects.create_user(
            email="commission@example.com",
            password="testpass123",
            organization=self.organization
        )
    
    def test_commission_model_calculation_precision(self):
        """Test that Commission model uses enhanced precision calculations"""
        
        from datetime import date
        
        commission = Commission(
            organization=self.organization,
            user=self.user,
            total_sales=Decimal('10000.00'),
            start_date=date.today(),
            end_date=date.today(),
            commission_rate=Decimal('7.50'),
            exchange_rate=Decimal('1.250000'),
            bonus=Decimal('100.00'),
            penalty=Decimal('25.00')
        )
        
        # Trigger calculation
        commission._calculate_amounts()
        
        # Verify precision of calculated fields
        self.assertEqual(commission.commission_amount.as_tuple().exponent, -2)
        self.assertEqual(commission.total_commission.as_tuple().exponent, -2)
        self.assertEqual(commission.total_receivable.as_tuple().exponent, -2)
        self.assertEqual(commission.converted_amount.as_tuple().exponent, -2)
        
        # Verify calculation accuracy
        # Base commission: 10000 * 0.075 = 750
        self.assertEqual(commission.commission_amount, Decimal('750.00'))
        
        # Converted commission: 750 * 1.25 = 937.50
        # Total commission with bonus: 937.50 + 100 = 1037.50
        self.assertEqual(commission.total_commission, Decimal('1037.50'))
        
        # Total receivable after penalty: 1037.50 - 25 = 1012.50
        self.assertEqual(commission.total_receivable, Decimal('1012.50'))
    
    def test_commission_validation_integration(self):
        """Test that Commission model validation uses enhanced financial validation"""
        
        from datetime import date
        
        # Test with invalid precision (too many decimal places)
        commission = Commission(
            organization=self.organization,
            user=self.user,
            total_sales=Decimal('10000.001'),  # Invalid precision
            start_date=date.today(),
            end_date=date.today(),
            commission_rate=Decimal('5.00'),
        )
        
        # Should handle precision validation
        try:
            commission.full_clean()
            commission._calculate_amounts()
            # If no exception, the value should be corrected
            self.assertEqual(commission.total_sales.as_tuple().exponent, -2)
        except ValidationError as e:
            # Or it should raise a helpful validation error
            self.assertIn('decimal places', str(e).lower())


if __name__ == '__main__':
    unittest.main()
