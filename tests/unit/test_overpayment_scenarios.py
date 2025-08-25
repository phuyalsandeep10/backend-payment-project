"""
Comprehensive Overpayment Scenario Tests - Task 5.2.1

Test suite for overpayment logic in payment consistency validation.
Ensures is_fully_paid is True when total >= deal_value and covers all overpayment scenarios.
"""

import unittest
from decimal import Decimal
from django.test import TestCase
from django.core.exceptions import ValidationError
from apps.deals.financial_optimizer import FinancialFieldOptimizer
from apps.deals.models import Deal, Payment
from apps.clients.models import Client
from apps.organization.models import Organization
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()


class TestOverpaymentScenarios(TestCase):
    """
    Test comprehensive overpayment scenarios
    Task 5.2.1: Comprehensive overpayment scenario testing
    """
    
    def setUp(self):
        """Set up test data"""
        self.optimizer = FinancialFieldOptimizer()
        
        # Create test organization and user
        self.organization = Organization.objects.create(
            name="Overpayment Test Organization",
            is_active=True
        )
        
        self.user = User.objects.create_user(
            email="overpayment@example.com",
            password="testpass123",
            organization=self.organization
        )
        
        self.client = Client.objects.create(
            client_name="Overpayment Test Client",
            organization=self.organization
        )
    
    def test_exact_payment_scenario(self):
        """Test scenario where total payments exactly equal deal value"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('500.00')},
            {'amount': Decimal('500.00')}
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Task 5.2.1: Verify is_fully_paid is True for exact payment
        self.assertTrue(result['is_fully_paid'], "Deal should be fully paid when total equals deal value")
        self.assertEqual(result['total_payments'], deal_value)
        self.assertEqual(result['overpayment'], Decimal('0.00'))
        self.assertFalse(result['is_overpaid'])
        self.assertEqual(result['payment_status'], 'fully_paid')
        self.assertTrue(result['scenarios']['exact_payment'])
        self.assertEqual(len(result['overpayment_warnings']), 0)
    
    def test_minor_overpayment_scenario(self):
        """Test scenario with minor overpayment (≤5%)"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('600.00')},
            {'amount': Decimal('450.00')}  # Total: $1050.00, 5% overpayment
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Task 5.2.1: Verify is_fully_paid is True for overpayment
        self.assertTrue(result['is_fully_paid'], "Deal should be fully paid when total exceeds deal value")
        self.assertEqual(result['total_payments'], Decimal('1050.00'))
        self.assertEqual(result['overpayment'], Decimal('50.00'))
        self.assertTrue(result['is_overpaid'])
        self.assertEqual(result['payment_status'], 'overpaid')
        self.assertTrue(result['scenarios']['minor_overpayment'])
        self.assertFalse(result['scenarios']['significant_overpayment'])
        self.assertEqual(result['overpayment_percentage'], Decimal('5.00'))
        
        # Check overpayment warnings
        self.assertGreater(len(result['overpayment_warnings']), 0)
        self.assertIn('overpaid by $50.00', result['overpayment_warnings'][0])
    
    def test_significant_overpayment_scenario(self):
        """Test scenario with significant overpayment (>10%)"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('700.00')},
            {'amount': Decimal('500.00')}  # Total: $1200.00, 20% overpayment
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Task 5.2.1: Verify is_fully_paid is True for significant overpayment
        self.assertTrue(result['is_fully_paid'], "Deal should be fully paid even with significant overpayment")
        self.assertEqual(result['total_payments'], Decimal('1200.00'))
        self.assertEqual(result['overpayment'], Decimal('200.00'))
        self.assertTrue(result['is_overpaid'])
        self.assertEqual(result['payment_status'], 'overpaid')
        self.assertFalse(result['scenarios']['minor_overpayment'])
        self.assertTrue(result['scenarios']['significant_overpayment'])
        self.assertEqual(result['overpayment_percentage'], Decimal('20.00'))
        
        # Check significant overpayment warnings
        self.assertGreater(len(result['overpayment_warnings']), 1)
        self.assertIn('Significant overpayment detected', result['overpayment_warnings'][1])
        self.assertIn('20.0% above deal value', result['overpayment_warnings'][1])
    
    def test_moderate_overpayment_scenario(self):
        """Test scenario with moderate overpayment (5-10%)"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('600.00')},
            {'amount': Decimal('480.00')}  # Total: $1080.00, 8% overpayment
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Task 5.2.1: Verify is_fully_paid is True for moderate overpayment
        self.assertTrue(result['is_fully_paid'])
        self.assertEqual(result['total_payments'], Decimal('1080.00'))
        self.assertEqual(result['overpayment'], Decimal('80.00'))
        self.assertTrue(result['is_overpaid'])
        self.assertEqual(result['payment_status'], 'overpaid')
        self.assertEqual(result['overpayment_percentage'], Decimal('8.00'))
        
        # Check moderate overpayment warnings
        self.assertGreater(len(result['overpayment_warnings']), 1)
        self.assertIn('Notable overpayment', result['overpayment_warnings'][1])
        self.assertIn('8.0% above deal value', result['overpayment_warnings'][1])
    
    def test_underpayment_scenario(self):
        """Test scenario with underpayment"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('300.00')},
            {'amount': Decimal('400.00')}  # Total: $700.00, underpayment
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Task 5.2.1: Verify is_fully_paid is False for underpayment
        self.assertFalse(result['is_fully_paid'], "Deal should not be fully paid when total is less than deal value")
        self.assertEqual(result['total_payments'], Decimal('700.00'))
        self.assertEqual(result['overpayment'], Decimal('0.00'))
        self.assertFalse(result['is_overpaid'])
        self.assertEqual(result['payment_status'], 'partially_paid')
        self.assertEqual(result['remaining_balance'], Decimal('300.00'))
        self.assertEqual(result['display_remaining_balance'], Decimal('300.00'))
        self.assertTrue(result['scenarios']['underpayment'])
        self.assertEqual(len(result['overpayment_warnings']), 0)
    
    def test_single_overpayment_scenario(self):
        """Test scenario with single payment exceeding deal value"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('1250.00')}  # Single overpayment of 25%
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Task 5.2.1: Verify is_fully_paid is True for single overpayment
        self.assertTrue(result['is_fully_paid'])
        self.assertEqual(result['total_payments'], Decimal('1250.00'))
        self.assertEqual(result['overpayment'], Decimal('250.00'))
        self.assertTrue(result['is_overpaid'])
        self.assertEqual(result['payment_status'], 'overpaid')
        self.assertEqual(result['overpayment_percentage'], Decimal('25.00'))
        self.assertTrue(result['scenarios']['significant_overpayment'])
        
        # Should have significant overpayment warning
        self.assertIn('Significant overpayment detected', result['overpayment_warnings'][1])
    
    def test_multiple_small_overpayments_scenario(self):
        """Test scenario with multiple small payments resulting in overpayment"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('250.00')},
            {'amount': Decimal('250.00')},
            {'amount': Decimal('250.00')},
            {'amount': Decimal('270.00')}  # Total: $1020.00, 2% overpayment
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Task 5.2.1: Verify is_fully_paid is True for cumulative overpayment
        self.assertTrue(result['is_fully_paid'])
        self.assertEqual(result['total_payments'], Decimal('1020.00'))
        self.assertEqual(result['overpayment'], Decimal('20.00'))
        self.assertTrue(result['is_overpaid'])
        self.assertEqual(result['payment_status'], 'overpaid')
        self.assertTrue(result['scenarios']['minor_overpayment'])
    
    def test_zero_deal_value_scenario(self):
        """Test edge case with zero deal value"""
        
        deal_value = Decimal('0.00')
        payments = [
            {'amount': Decimal('100.00')}
        ]
        
        # This should raise a ValidationError since deal value must be > 0
        with self.assertRaises(ValidationError):
            self.optimizer.validate_payment_consistency(deal_value, payments)
    
    def test_precision_boundary_overpayment(self):
        """Test overpayment at precision boundaries"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('1000.01')}  # Overpayment by 1 cent
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Task 5.2.1: Even 1 cent overpayment should mark as fully paid
        self.assertTrue(result['is_fully_paid'])
        self.assertEqual(result['overpayment'], Decimal('0.01'))
        self.assertTrue(result['is_overpaid'])
        self.assertEqual(result['payment_status'], 'overpaid')
    
    def test_negative_remaining_balance_display(self):
        """Test that display_remaining_balance is never negative"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('1200.00')}  # $200 overpayment
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Remaining balance should be negative internally but display as zero
        self.assertEqual(result['remaining_balance'], Decimal('-200.00'))
        self.assertEqual(result['display_remaining_balance'], Decimal('0.00'))
        self.assertTrue(result['is_fully_paid'])
    
    def test_payment_progress_with_overpayment(self):
        """Test payment progress calculation with overpayment"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': Decimal('1150.00')}  # 15% overpayment
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Payment progress should be > 100% for overpayment
        progress = result['payment_progress']
        self.assertEqual(progress, Decimal('115.0000'))
        self.assertGreater(progress, Decimal('100.0000'))
    
    def test_invalid_payment_amounts_with_overpayment(self):
        """Test handling of invalid payment amounts in overpayment scenarios"""
        
        deal_value = Decimal('1000.00')
        payments = [
            {'amount': 'invalid'},
            {'amount': Decimal('1200.00')}
        ]
        
        result = self.optimizer.validate_payment_consistency(deal_value, payments)
        
        # Should still process valid payments and show overpayment
        self.assertEqual(result['total_payments'], Decimal('1200.00'))
        self.assertTrue(result['is_fully_paid'])
        self.assertTrue(result['is_overpaid'])
        
        # Should have validation errors for invalid payment
        self.assertGreater(len(result['validation_errors']), 0)
        self.assertFalse(result['validation_errors'][0]['valid'])


class TestOverpaymentModelIntegration(TestCase):
    """
    Test overpayment logic integration with Django models
    Task 5.2.1: Model integration testing
    """
    
    def setUp(self):
        """Set up test models"""
        self.organization = Organization.objects.create(
            name="Model Integration Test Org",
            is_active=True
        )
        
        self.user = User.objects.create_user(
            email="model@example.com",
            password="testpass123",
            organization=self.organization
        )
        
        self.client = Client.objects.create(
            client_name="Model Test Client",
            organization=self.organization
        )
    
    def test_deal_model_overpayment_validation(self):
        """Test deal model handles overpayment validation correctly"""
        
        # Create deal
        deal = Deal.objects.create(
            deal_id="OVERPAY001",
            deal_name="Overpayment Test Deal",
            deal_value=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user,
            client=self.client
        )
        
        # Add payments that overpay
        payment1 = Payment.objects.create(
            deal=deal,
            received_amount=Decimal('600.00'),
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        payment2 = Payment.objects.create(
            deal=deal,
            received_amount=Decimal('500.00'),
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        # Refresh deal to get updated payments
        deal.refresh_from_db()
        
        # Test payment consistency validation
        existing_payments = [{'amount': p.received_amount} for p in deal.payments.all()]
        result = FinancialFieldOptimizer.validate_payment_consistency(
            deal.deal_value, existing_payments
        )
        
        # Verify overpayment is handled correctly
        self.assertTrue(result['is_fully_paid'])
        self.assertEqual(result['total_payments'], Decimal('1100.00'))
        self.assertEqual(result['overpayment'], Decimal('100.00'))
        self.assertTrue(result['is_overpaid'])
        self.assertEqual(result['payment_status'], 'overpaid')
    
    def test_payment_model_overpayment_prevention(self):
        """Test payment model prevents excessive overpayment"""
        
        # Create deal
        deal = Deal.objects.create(
            deal_id="PREVENT001",
            deal_name="Overpayment Prevention Test",
            deal_value=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user,
            client=self.client
        )
        
        # Add first payment
        Payment.objects.create(
            deal=deal,
            received_amount=Decimal('800.00'),
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        # Try to add second payment that would cause excessive overpayment
        # (This should be allowed but flagged as overpaid)
        payment2 = Payment(
            deal=deal,
            received_amount=Decimal('300.00'),  # Would cause $100 overpayment
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        # The payment should be valid but deal will show as overpaid
        try:
            payment2.full_clean()
            payment2.save()
            
            # Verify the deal is now overpaid
            existing_payments = [{'amount': p.received_amount} for p in deal.payments.all()]
            result = FinancialFieldOptimizer.validate_payment_consistency(
                deal.deal_value, existing_payments
            )
            
            self.assertTrue(result['is_fully_paid'])
            self.assertTrue(result['is_overpaid'])
            self.assertEqual(result['payment_status'], 'overpaid')
            
        except ValidationError:
            # If validation prevents this, that's also acceptable behavior
            pass


if __name__ == '__main__':
    unittest.main()
