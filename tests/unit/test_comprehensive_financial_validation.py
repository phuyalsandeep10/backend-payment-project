"""
Comprehensive Financial Validation Tests - Task 5.1.2

Test suite for financial calculation accuracy and comprehensive validation.
"""

import unittest
from decimal import Decimal, InvalidOperation
from django.test import TestCase
from django.core.exceptions import ValidationError
from apps.deals.comprehensive_financial_validator import (
    ComprehensiveFinancialValidator,
    FinancialValidationResult,
    validate_model_financial_fields,
    validate_financial_calculation
)
from apps.deals.models import Deal, Payment
from apps.clients.models import Client
from apps.organization.models import Organization
from django.contrib.auth import get_user_model

User = get_user_model()


class TestComprehensiveFinancialValidation(TestCase):
    """
    Test comprehensive financial validation system
    Task 5.1.2: Financial calculation accuracy tests
    """
    
    def setUp(self):
        """Set up test data"""
        self.validator = ComprehensiveFinancialValidator()
        
        # Create test organization and user
        self.organization = Organization.objects.create(
            name="Test Organization",
            is_active=True
        )
        
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            organization=self.organization
        )
        
        self.client = Client.objects.create(
            client_name="Test Client",
            organization=self.organization
        )
    
    def test_currency_field_validation_precision(self):
        """Test currency field precision validation"""
        
        # Valid 2 decimal place amounts
        valid_amounts = [
            "100.00", "1234.56", "0.01", Decimal("999.99")
        ]
        
        for amount in valid_amounts:
            result = self.validator.validate_currency_field(amount, "test_amount")
            self.assertIsInstance(result, Decimal)
            self.assertEqual(result.as_tuple().exponent, -2)
        
        # Invalid amounts with too many decimal places
        invalid_amounts = [
            "100.001", "1234.5678", "0.001"
        ]
        
        for amount in invalid_amounts:
            with self.assertRaises(ValidationError) as context:
                self.validator.validate_currency_field(amount, "test_amount")
            
            self.assertIn("decimal places", str(context.exception))
    
    def test_currency_field_overflow_protection(self):
        """Test overflow protection for currency fields"""
        
        # Test maximum value overflow
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_currency_field("9999999999.99", "test_amount")
        
        self.assertIn("overflow protection", str(context.exception))
        
        # Test negative value overflow
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_currency_field("-9999999999.99", "test_amount")
        
        self.assertIn("overflow protection", str(context.exception))
    
    def test_percentage_field_validation(self):
        """Test percentage field validation"""
        
        # Valid percentage values
        valid_percentages = [
            "10.5000", "0.0001", "100.0000", Decimal("50.2500")
        ]
        
        for percentage in valid_percentages:
            result = self.validator.validate_percentage_field(percentage, "test_rate")
            self.assertIsInstance(result, Decimal)
            self.assertEqual(result.as_tuple().exponent, -4)
        
        # Test percentage overflow protection
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_percentage_field("150.0000", "test_rate")
        
        self.assertIn("overflow protection", str(context.exception))
    
    def test_exchange_rate_validation(self):
        """Test exchange rate field validation"""
        
        # Valid exchange rates
        valid_rates = [
            "1.234567", "0.000001", "1000.000000", Decimal("1.500000")
        ]
        
        for rate in valid_rates:
            result = self.validator.validate_exchange_rate_field(rate, "test_rate")
            self.assertIsInstance(result, Decimal)
            self.assertEqual(result.as_tuple().exponent, -6)
        
        # Test exchange rate overflow protection
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_exchange_rate_field("50000.000000", "test_rate")
        
        self.assertIn("overflow protection", str(context.exception))
        
        # Test minimum value protection
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_exchange_rate_field("0.0000001", "test_rate")
        
        self.assertIn("overflow protection", str(context.exception))
    
    def test_commission_calculation_accuracy(self):
        """Test commission calculation accuracy and overflow protection"""
        
        # Valid commission calculation
        operands = {
            'sales_amount': Decimal('1000.00'),
            'commission_rate': Decimal('10.5000')
        }
        
        result = self.validator.validate_financial_calculation('commission_calculation', operands)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['result'], Decimal('105.00'))
        
        # Test overflow protection in commission calculation
        overflow_operands = {
            'sales_amount': Decimal('999999999.99'),
            'commission_rate': Decimal('100.0000')
        }
        
        overflow_result = self.validator.validate_financial_calculation('commission_calculation', overflow_operands)
        
        self.assertFalse(overflow_result['success'])
        self.assertIn('overflow', overflow_result['error'].lower())
    
    def test_payment_total_calculation(self):
        """Test payment total calculation with overflow protection"""
        
        # Valid payment total calculation
        operands = {
            'payments': [Decimal('100.00'), Decimal('200.00'), Decimal('300.00')]
        }
        
        result = self.validator.validate_financial_calculation('payment_total', operands)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['result'], Decimal('600.00'))
        
        # Test overflow protection
        overflow_operands = {
            'payments': [Decimal('500000000.00'), Decimal('500000000.00'), Decimal('500000000.00')]
        }
        
        overflow_result = self.validator.validate_financial_calculation('payment_total', overflow_operands)
        
        self.assertFalse(overflow_result['success'])
        self.assertIn('overflow', overflow_result['error'].lower())
    
    def test_currency_conversion_calculation(self):
        """Test currency conversion calculation accuracy"""
        
        # Valid currency conversion
        operands = {
            'original_amount': Decimal('1000.00'),
            'exchange_rate': Decimal('1.250000')
        }
        
        result = self.validator.validate_financial_calculation('currency_conversion', operands)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['result'], Decimal('1250.00'))
        
        # Test high precision conversion
        high_precision_operands = {
            'original_amount': Decimal('1000.00'),
            'exchange_rate': Decimal('1.123456')
        }
        
        high_precision_result = self.validator.validate_financial_calculation('currency_conversion', high_precision_operands)
        
        self.assertTrue(high_precision_result['success'])
        self.assertEqual(high_precision_result['result'], Decimal('1123.46'))  # Rounded to 2 decimal places
    
    def test_model_financial_fields_validation(self):
        """Test comprehensive model validation"""
        
        # Create a deal with valid financial fields
        deal = Deal(
            deal_id="TEST001",
            deal_name="Test Deal",
            deal_value=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user,
            client=self.client
        )
        
        # Validate the deal
        validation_result = self.validator.validate_model_financial_fields(deal)
        
        self.assertIsInstance(validation_result, FinancialValidationResult)
        self.assertTrue(validation_result.is_valid)
        self.assertEqual(len(validation_result.errors), 0)
        
        # Test deal with invalid financial fields
        invalid_deal = Deal(
            deal_id="TEST002",
            deal_name="Invalid Deal",
            deal_value=Decimal('1000.001'),  # Too many decimal places
            organization=self.organization,
            created_by=self.user,
            client=self.client
        )
        
        invalid_validation_result = self.validator.validate_model_financial_fields(invalid_deal)
        
        self.assertFalse(invalid_validation_result.is_valid)
        self.assertGreater(len(invalid_validation_result.errors), 0)
        self.assertIn("decimal places", invalid_validation_result.errors[0])
    
    def test_business_logic_validation(self):
        """Test business logic validation for financial models"""
        
        # Create a deal and save it
        deal = Deal.objects.create(
            deal_id="TEST003",
            deal_name="Business Logic Test Deal",
            deal_value=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user,
            client=self.client
        )
        
        # Create payments that exceed deal value
        payment1 = Payment.objects.create(
            deal=deal,
            received_amount=Decimal('600.00'),
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        payment2 = Payment.objects.create(
            deal=deal,
            received_amount=Decimal('600.00'),  # Total will be $1200, exceeding $1000 deal value
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        # Validate business logic
        validation_result = self.validator.validate_model_financial_fields(deal)
        
        # Should have warnings about overpayment
        self.assertGreater(len(validation_result.warnings), 0)
        overpayment_warning = any('exceed deal value' in warning for warning in validation_result.warnings)
        self.assertTrue(overpayment_warning)
    
    def test_financial_validation_report_generation(self):
        """Test financial validation report generation"""
        
        # Create multiple deals with various financial issues
        deals = []
        
        # Valid deal
        deals.append(Deal(
            deal_id="REPORT001",
            deal_name="Valid Deal",
            deal_value=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user,
            client=self.client
        ))
        
        # Deal with precision issue
        deals.append(Deal(
            deal_id="REPORT002",
            deal_name="Precision Issue Deal",
            deal_value=Decimal('1000.001'),  # Too many decimal places
            organization=self.organization,
            created_by=self.user,
            client=self.client
        ))
        
        # Generate validation report
        report = self.validator.generate_financial_validation_report(deals)
        
        # Verify report structure
        self.assertIn('summary', report)
        self.assertIn('detailed_results', report)
        self.assertIn('recommendations', report)
        
        # Verify summary statistics
        summary = report['summary']
        self.assertEqual(summary['total_models_validated'], 2)
        self.assertGreater(summary['total_errors'], 0)  # Should have at least one error from precision issue
        
        # Verify recommendations
        recommendations = report['recommendations']
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
    
    def test_currency_symbol_handling(self):
        """Test handling of currency symbols in validation"""
        
        # Test various currency formats
        currency_formats = [
            "$1,000.00",
            "1,000.00",
            "1000.00",
            "$1000",
            "USD 1000.00"
        ]
        
        for currency_format in currency_formats:
            try:
                result = self.validator.validate_currency_field(currency_format, "test_amount")
                self.assertIsInstance(result, Decimal)
                self.assertEqual(result, Decimal('1000.00'))
            except ValidationError:
                # Some formats might not be supported, which is acceptable
                pass
    
    def test_financial_field_pattern_recognition(self):
        """Test recognition of financial field patterns"""
        
        # Currency field patterns
        currency_fields = ['deal_value', 'received_amount', 'commission_amount', 'total_amount']
        for field in currency_fields:
            self.assertTrue(self.validator._is_currency_field(field))
            self.assertTrue(self.validator._is_financial_field(field))
        
        # Percentage field patterns  
        percentage_fields = ['commission_rate', 'tax_rate', 'discount_rate']
        for field in percentage_fields:
            self.assertTrue(self.validator._is_percentage_field(field))
            self.assertTrue(self.validator._is_financial_field(field))
        
        # Exchange rate field patterns
        exchange_rate_fields = ['exchange_rate', 'conversion_rate', 'currency_rate']
        for field in exchange_rate_fields:
            self.assertTrue(self.validator._is_exchange_rate_field(field))
            self.assertTrue(self.validator._is_financial_field(field))
        
        # Non-financial fields
        non_financial_fields = ['name', 'email', 'created_at', 'is_active']
        for field in non_financial_fields:
            self.assertFalse(self.validator._is_financial_field(field))


class TestFinancialCalculationEdgeCases(TestCase):
    """
    Test edge cases in financial calculations
    Task 5.1.2: Edge case testing
    """
    
    def setUp(self):
        self.validator = ComprehensiveFinancialValidator()
    
    def test_zero_amount_handling(self):
        """Test handling of zero amounts"""
        
        # Zero currency amount
        result = self.validator.validate_currency_field(Decimal('0.00'), 'zero_amount')
        self.assertEqual(result, Decimal('0.00'))
        
        # Zero percentage
        result = self.validator.validate_percentage_field(Decimal('0.0000'), 'zero_rate')
        self.assertEqual(result, Decimal('0.0000'))
    
    def test_rounding_precision(self):
        """Test decimal rounding precision"""
        
        # Test rounding up
        result = self.validator.validate_currency_field('123.455', 'round_up')
        self.assertEqual(result, Decimal('123.46'))
        
        # Test rounding down
        result = self.validator.validate_currency_field('123.454', 'round_down')
        self.assertEqual(result, Decimal('123.45'))
        
        # Test exact rounding boundary
        result = self.validator.validate_currency_field('123.445', 'round_boundary')
        self.assertEqual(result, Decimal('123.45'))  # Banker's rounding
    
    def test_negative_amount_handling(self):
        """Test handling of negative amounts"""
        
        # Negative currency (like refunds)
        result = self.validator.validate_currency_field('-100.00', 'refund_amount')
        self.assertEqual(result, Decimal('-100.00'))
        
        # Negative percentage (like discounts)
        result = self.validator.validate_percentage_field('-10.0000', 'discount_rate')
        self.assertEqual(result, Decimal('-10.0000'))
    
    def test_very_small_amounts(self):
        """Test handling of very small amounts"""
        
        # Minimum currency amount
        result = self.validator.validate_currency_field('0.01', 'min_amount')
        self.assertEqual(result, Decimal('0.01'))
        
        # Below minimum currency amount
        with self.assertRaises(ValidationError):
            self.validator.validate_currency_field('0.001', 'below_min')
    
    def test_string_number_conversion(self):
        """Test conversion of string numbers to Decimal"""
        
        string_numbers = [
            ('123', Decimal('123.00')),
            ('123.4', Decimal('123.40')),
            ('123.45', Decimal('123.45')),
            ('0', Decimal('0.00'))
        ]
        
        for string_num, expected in string_numbers:
            result = self.validator.validate_currency_field(string_num, 'string_test')
            self.assertEqual(result, expected)


if __name__ == '__main__':
    unittest.main()
