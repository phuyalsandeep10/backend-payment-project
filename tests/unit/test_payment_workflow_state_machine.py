"""
Payment Workflow State Machine Tests - Task 5.2.2

Test suite for payment status transitions, workflow state management, 
and enhanced payment progress calculation.
"""

import unittest
from decimal import Decimal
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.utils import timezone
from apps.deals.financial_optimizer import FinancialFieldOptimizer
from apps.deals.models import Deal, Payment
from apps.clients.models import Client
from apps.organization.models import Organization
from django.contrib.auth import get_user_model

User = get_user_model()


class TestPaymentStatusTransitions(TestCase):
    """
    Test payment status transition validation
    Task 5.2.2: Payment status transition validation
    """
    
    def setUp(self):
        """Set up test data"""
        self.optimizer = FinancialFieldOptimizer()
    
    def test_valid_status_transitions(self):
        """Test valid payment status transitions"""
        
        # Test pending to partial_payment
        payment_data = {
            'deal_value': Decimal('1000.00'),
            'total_payments': Decimal('500.00')
        }
        
        result = self.optimizer.validate_payment_status_transition(
            'pending', 'partial_payment', payment_data
        )
        
        self.assertTrue(result['valid_transition'])
        self.assertEqual(len(result['errors']), 0)
        self.assertTrue(result['transition_allowed'])
        self.assertTrue(result['payment_data_consistent'])
    
    def test_invalid_status_transitions(self):
        """Test invalid payment status transitions"""
        
        payment_data = {
            'deal_value': Decimal('1000.00'),
            'total_payments': Decimal('500.00')
        }
        
        # Test invalid transition from fully_paid to partial_payment
        result = self.optimizer.validate_payment_status_transition(
            'fully_paid', 'partial_payment', payment_data
        )
        
        self.assertFalse(result['valid_transition'])
        self.assertGreater(len(result['errors']), 0)
        self.assertFalse(result['transition_allowed'])
        self.assertIn('Invalid transition', result['errors'][0])
    
    def test_status_transition_with_payment_data_mismatch(self):
        """Test status transition that doesn't match payment data"""
        
        # Payment data shows fully paid but status is partial_payment
        payment_data = {
            'deal_value': Decimal('1000.00'),
            'total_payments': Decimal('1000.00')  # Fully paid
        }
        
        result = self.optimizer.validate_payment_status_transition(
            'pending', 'partial_payment', payment_data
        )
        
        # Transition is allowed but should have warnings
        self.assertTrue(result['valid_transition'])
        self.assertGreater(len(result['warnings']), 0)
        self.assertFalse(result['payment_data_consistent'])
        self.assertIn('may not match payment data', result['warnings'][0])
    
    def test_administrative_status_transitions(self):
        """Test administrative status transitions (refunded, cancelled)"""
        
        payment_data = {
            'deal_value': Decimal('1000.00'),
            'total_payments': Decimal('1000.00')
        }
        
        # Test transition to refunded (administrative status)
        result = self.optimizer.validate_payment_status_transition(
            'fully_paid', 'refunded', payment_data
        )
        
        self.assertTrue(result['valid_transition'])
        self.assertEqual(len(result['warnings']), 0)  # No warnings for admin statuses
        self.assertTrue(result['transition_allowed'])
    
    def test_invalid_status_names(self):
        """Test transitions with invalid status names"""
        
        payment_data = {
            'deal_value': Decimal('1000.00'),
            'total_payments': Decimal('500.00')
        }
        
        result = self.optimizer.validate_payment_status_transition(
            'invalid_status', 'partial_payment', payment_data
        )
        
        self.assertFalse(result['valid_transition'])
        self.assertIn('Invalid current status', result['errors'][0])
    
    def test_restart_transitions_after_refund(self):
        """Test that deals can restart after refund or cancellation"""
        
        payment_data = {
            'deal_value': Decimal('1000.00'),
            'total_payments': Decimal('0.00')
        }
        
        # Test refunded to pending (restart)
        result = self.optimizer.validate_payment_status_transition(
            'refunded', 'pending', payment_data
        )
        
        self.assertTrue(result['valid_transition'])
        self.assertTrue(result['transition_allowed'])
        
        # Test cancelled to pending (restart)
        result = self.optimizer.validate_payment_status_transition(
            'cancelled', 'pending', payment_data
        )
        
        self.assertTrue(result['valid_transition'])
        self.assertTrue(result['transition_allowed'])


class TestPaymentWorkflowStateMachine(TestCase):
    """
    Test payment workflow state machine
    Task 5.2.2: Payment workflow state machine tests
    """
    
    def setUp(self):
        """Set up test data"""
        self.optimizer = FinancialFieldOptimizer()
        self.deal_value = Decimal('1000.00')
    
    def test_awaiting_first_payment_state(self):
        """Test workflow state with no payments"""
        
        payments = []
        
        workflow_state = self.optimizer.calculate_payment_workflow_state(
            self.deal_value, payments
        )
        
        self.assertEqual(workflow_state['primary_state'], 'awaiting_first_payment')
        self.assertEqual(workflow_state['payment_ratio'], Decimal('0'))
        self.assertEqual(workflow_state['workflow_completion'], Decimal('0'))
        self.assertIn('record_payment', workflow_state['recommended_actions'])
        
        # Check next possible states
        next_states = workflow_state['next_possible_states']
        state_names = [state['state'] for state in next_states]
        self.assertIn('initial_payment_received', state_names)
        self.assertIn('cancelled', state_names)
    
    def test_initial_payment_received_state(self):
        """Test workflow state with initial payment (< 25%)"""
        
        payments = [
            {'amount': Decimal('200.00')}  # 20% of deal value
        ]
        
        workflow_state = self.optimizer.calculate_payment_workflow_state(
            self.deal_value, payments
        )
        
        self.assertEqual(workflow_state['primary_state'], 'initial_payment_received')
        self.assertEqual(workflow_state['payment_ratio'], Decimal('0.2'))
        self.assertEqual(workflow_state['workflow_completion'], Decimal('20.00'))
        self.assertIn('record_additional_payment', workflow_state['recommended_actions'])
        
        # Verify payment progress calculation
        progress = workflow_state['payment_consistency']['payment_progress']
        self.assertEqual(progress, Decimal('20.0000'))
    
    def test_substantial_payment_received_state(self):
        """Test workflow state with substantial payment (25-75%)"""
        
        payments = [
            {'amount': Decimal('300.00')},
            {'amount': Decimal('200.00')}  # Total: 50% of deal value
        ]
        
        workflow_state = self.optimizer.calculate_payment_workflow_state(
            self.deal_value, payments
        )
        
        self.assertEqual(workflow_state['primary_state'], 'substantial_payment_received')
        self.assertEqual(workflow_state['payment_ratio'], Decimal('0.5'))
        self.assertEqual(workflow_state['workflow_completion'], Decimal('50.00'))
        self.assertIn('record_final_payment', workflow_state['recommended_actions'])
    
    def test_near_completion_state(self):
        """Test workflow state near completion (75-99%)"""
        
        payments = [
            {'amount': Decimal('500.00')},
            {'amount': Decimal('350.00')}  # Total: 85% of deal value
        ]
        
        workflow_state = self.optimizer.calculate_payment_workflow_state(
            self.deal_value, payments
        )
        
        self.assertEqual(workflow_state['primary_state'], 'near_completion')
        self.assertEqual(workflow_state['payment_ratio'], Decimal('0.85'))
        self.assertEqual(workflow_state['workflow_completion'], Decimal('85.00'))
        self.assertIn('prepare_completion', workflow_state['recommended_actions'])
    
    def test_completed_state(self):
        """Test workflow state when exactly paid"""
        
        payments = [
            {'amount': Decimal('600.00')},
            {'amount': Decimal('400.00')}  # Total: 100% of deal value
        ]
        
        workflow_state = self.optimizer.calculate_payment_workflow_state(
            self.deal_value, payments
        )
        
        self.assertEqual(workflow_state['primary_state'], 'completed')
        self.assertEqual(workflow_state['payment_ratio'], Decimal('1.0'))
        self.assertEqual(workflow_state['workflow_completion'], Decimal('100.00'))
        self.assertIn('generate_receipt', workflow_state['recommended_actions'])
        
        # Check next possible states
        next_states = workflow_state['next_possible_states']
        state_names = [state['state'] for state in next_states]
        self.assertIn('overpaid', state_names)
        self.assertIn('refunded', state_names)
    
    def test_overpaid_state(self):
        """Test workflow state when overpaid"""
        
        payments = [
            {'amount': Decimal('700.00')},
            {'amount': Decimal('500.00')}  # Total: 120% of deal value
        ]
        
        workflow_state = self.optimizer.calculate_payment_workflow_state(
            self.deal_value, payments
        )
        
        self.assertEqual(workflow_state['primary_state'], 'overpaid')
        self.assertEqual(workflow_state['payment_ratio'], Decimal('1.2'))
        self.assertGreater(workflow_state['workflow_completion'], Decimal('100.00'))
        self.assertIn('issue_refund', workflow_state['recommended_actions'])
        
        # Check overpayment description
        description = workflow_state['current_states'][0]['description']
        self.assertIn('overpaid by $200.00', description)
    
    def test_administrative_states(self):
        """Test workflow states with administrative statuses"""
        
        payments = [
            {'amount': Decimal('500.00')}
        ]
        
        # Test cancelled state
        workflow_state = self.optimizer.calculate_payment_workflow_state(
            self.deal_value, payments, current_status='cancelled'
        )
        
        # Should have both primary workflow state and administrative state
        states = workflow_state['current_states']
        state_names = [state['state'] for state in states]
        self.assertIn('cancelled', state_names)
        self.assertIn('substantial_payment_received', state_names)
    
    def test_state_transition_history(self):
        """Test generation of state transition history"""
        
        payments = [
            {'amount': Decimal('300.00'), 'timestamp': '2023-01-01'},
            {'amount': Decimal('400.00'), 'timestamp': '2023-01-15'},
            {'amount': Decimal('300.00'), 'timestamp': '2023-02-01'}
        ]
        
        workflow_state = self.optimizer.calculate_payment_workflow_state(
            self.deal_value, payments
        )
        
        transition_history = workflow_state['state_transition_history']
        
        self.assertEqual(len(transition_history), 3)
        
        # Check first transition
        self.assertEqual(transition_history[0]['payment_amount'], Decimal('300.00'))
        self.assertEqual(transition_history[0]['cumulative_amount'], Decimal('300.00'))
        
        # Check second transition
        self.assertEqual(transition_history[1]['payment_amount'], Decimal('400.00'))
        self.assertEqual(transition_history[1]['cumulative_amount'], Decimal('700.00'))
        
        # Check final transition (overpaid state)
        self.assertEqual(transition_history[2]['cumulative_amount'], Decimal('1000.00'))
    
    def test_workflow_with_invalid_payments(self):
        """Test workflow state calculation with invalid payments"""
        
        payments = [
            {'amount': 'invalid'},
            {'amount': Decimal('500.00')},
            {'amount': None}
        ]
        
        workflow_state = self.optimizer.calculate_payment_workflow_state(
            self.deal_value, payments
        )
        
        # Should still calculate workflow state based on valid payments
        self.assertEqual(workflow_state['primary_state'], 'substantial_payment_received')
        
        # Should have validation errors in payment consistency
        payment_consistency = workflow_state['payment_consistency']
        self.assertGreater(len(payment_consistency['validation_errors']), 0)
    
    def test_next_workflow_states_logic(self):
        """Test next workflow states logic for different scenarios"""
        
        # Test from awaiting_first_payment
        next_states = self.optimizer._get_next_workflow_states(
            'awaiting_first_payment', Decimal('0'), Decimal('0')
        )
        self.assertEqual(len(next_states), 2)
        
        # Test from completed
        next_states = self.optimizer._get_next_workflow_states(
            'completed', Decimal('1'), Decimal('0')
        )
        triggers = [state['trigger'] for state in next_states]
        self.assertIn('additional_payment', triggers)
        self.assertIn('refund_process', triggers)


class TestEnhancedPaymentProgressCalculation(TestCase):
    """
    Test enhanced payment progress calculation
    Task 5.2.2: Enhanced payment progress calculation
    """
    
    def setUp(self):
        """Set up test data"""
        self.optimizer = FinancialFieldOptimizer()
    
    def test_precise_progress_calculation(self):
        """Test progress calculation with high precision"""
        
        # Test precise calculation
        progress = self.optimizer.calculate_payment_progress(
            Decimal('333.33'), Decimal('1000.00')
        )
        
        # Should be exactly 33.3300% (4 decimal places)
        self.assertEqual(progress, Decimal('33.3300'))
    
    def test_progress_calculation_edge_cases(self):
        """Test progress calculation edge cases"""
        
        # Zero deal value
        progress = self.optimizer.calculate_payment_progress(
            Decimal('100.00'), Decimal('0.00')
        )
        self.assertEqual(progress, Decimal('0.0000'))
        
        # Zero payment
        progress = self.optimizer.calculate_payment_progress(
            Decimal('0.00'), Decimal('1000.00')
        )
        self.assertEqual(progress, Decimal('0.0000'))
        
        # Overpayment scenario
        progress = self.optimizer.calculate_payment_progress(
            Decimal('1200.00'), Decimal('1000.00')
        )
        self.assertEqual(progress, Decimal('120.0000'))
    
    def test_progress_calculation_with_string_inputs(self):
        """Test progress calculation with string number inputs"""
        
        progress = self.optimizer.calculate_payment_progress(
            '750.50', Decimal('1000.00')
        )
        
        # Should handle string conversion properly
        self.assertEqual(progress, Decimal('75.0500'))
    
    def test_progress_calculation_precision_rounding(self):
        """Test progress calculation rounding to 4 decimal places"""
        
        # Test rounding scenario
        progress = self.optimizer.calculate_payment_progress(
            Decimal('333.333333'), Decimal('1000.00')
        )
        
        # Should round to 4 decimal places
        self.assertEqual(progress.as_tuple().exponent, -4)
        self.assertEqual(progress, Decimal('33.3333'))


class TestPaymentWorkflowIntegration(TestCase):
    """
    Test integration of payment workflow with Django models
    Task 5.2.2: Integration testing
    """
    
    def setUp(self):
        """Set up test models"""
        self.organization = Organization.objects.create(
            name="Workflow Test Org",
            is_active=True
        )
        
        self.user = User.objects.create_user(
            email="workflow@example.com",
            password="testpass123",
            organization=self.organization
        )
        
        self.client = Client.objects.create(
            client_name="Workflow Test Client",
            organization=self.organization
        )
    
    def test_deal_workflow_progression(self):
        """Test workflow progression through various payment states"""
        
        # Create deal
        deal = Deal.objects.create(
            deal_id="WORKFLOW001",
            deal_name="Workflow Test Deal",
            deal_value=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user,
            client=self.client
        )
        
        # Stage 1: No payments - awaiting first payment
        payments = []
        workflow_state = FinancialFieldOptimizer.calculate_payment_workflow_state(
            deal.deal_value, payments
        )
        self.assertEqual(workflow_state['primary_state'], 'awaiting_first_payment')
        
        # Stage 2: Add first payment - initial payment received
        payment1 = Payment.objects.create(
            deal=deal,
            received_amount=Decimal('200.00'),
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        payments = [{'amount': payment1.received_amount}]
        workflow_state = FinancialFieldOptimizer.calculate_payment_workflow_state(
            deal.deal_value, payments
        )
        self.assertEqual(workflow_state['primary_state'], 'initial_payment_received')
        
        # Stage 3: Add substantial payment - substantial payment received
        payment2 = Payment.objects.create(
            deal=deal,
            received_amount=Decimal('400.00'),
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        payments = [
            {'amount': payment1.received_amount},
            {'amount': payment2.received_amount}
        ]
        workflow_state = FinancialFieldOptimizer.calculate_payment_workflow_state(
            deal.deal_value, payments
        )
        self.assertEqual(workflow_state['primary_state'], 'substantial_payment_received')
        
        # Stage 4: Add final payment - completed
        payment3 = Payment.objects.create(
            deal=deal,
            received_amount=Decimal('400.00'),
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        payments = [
            {'amount': payment1.received_amount},
            {'amount': payment2.received_amount},
            {'amount': payment3.received_amount}
        ]
        workflow_state = FinancialFieldOptimizer.calculate_payment_workflow_state(
            deal.deal_value, payments
        )
        self.assertEqual(workflow_state['primary_state'], 'completed')
    
    def test_status_transition_validation_integration(self):
        """Test status transition validation with actual payment data"""
        
        deal = Deal.objects.create(
            deal_id="STATUS001",
            deal_name="Status Transition Test",
            deal_value=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user,
            client=self.client
        )
        
        # Add partial payment
        Payment.objects.create(
            deal=deal,
            received_amount=Decimal('500.00'),
            payment_date=timezone.now().date(),
            organization=self.organization
        )
        
        # Validate transition from pending to partial_payment
        payment_data = {
            'deal_value': deal.deal_value,
            'total_payments': Decimal('500.00')
        }
        
        result = FinancialFieldOptimizer.validate_payment_status_transition(
            'pending', 'partial_payment', payment_data
        )
        
        self.assertTrue(result['valid_transition'])
        self.assertTrue(result['payment_data_consistent'])


if __name__ == '__main__':
    unittest.main()
