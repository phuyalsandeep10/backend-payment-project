"""
Financial Field Optimization Service
Provides enhanced financial field handling, validation, and calculations for Deal and Commission models
"""

from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from typing import Dict, Any, List, Optional, Tuple
import logging

logger = logging.getLogger('financial')

class FinancialFieldOptimizer:
    """
    Service for optimizing financial field handling with proper decimal arithmetic,
    validation, and integrity checks
    """
    
    # Precision settings for different financial operations
    CURRENCY_PRECISION = Decimal('0.01')  # 2 decimal places for currency
    PERCENTAGE_PRECISION = Decimal('0.0001')  # 4 decimal places for percentages
    EXCHANGE_RATE_PRECISION = Decimal('0.000001')  # 6 decimal places for exchange rates
    
    # Maximum allowed values to prevent overflow
    MAX_DEAL_VALUE = Decimal('999999999.99')  # ~1 billion
    MAX_COMMISSION_RATE = Decimal('100.00')  # 100%
    MAX_EXCHANGE_RATE = Decimal('10000.00')  # 10,000:1 exchange rate
    
    @classmethod
    def validate_decimal_field(cls, value, field_name: str, max_value: Decimal = None, 
                              min_value: Decimal = None, precision: Decimal = None) -> Decimal:
        """
        Validate and normalize decimal field values with proper precision
        """
        if value is None:
            return Decimal('0.00')
        
        try:
            # Convert to Decimal if not already
            if not isinstance(value, Decimal):
                decimal_value = Decimal(str(value))
            else:
                decimal_value = value
            
            # Apply precision rounding if specified
            if precision:
                decimal_value = decimal_value.quantize(precision, rounding=ROUND_HALF_UP)
            
            # Validate range
            if min_value is not None and decimal_value < min_value:
                raise ValidationError(f'{field_name} must be at least {min_value}')
            
            if max_value is not None and decimal_value > max_value:
                raise ValidationError(f'{field_name} cannot exceed {max_value}')
            
            return decimal_value
            
        except (InvalidOperation, ValueError) as e:
            raise ValidationError(f'Invalid {field_name}: {str(e)}')
    
    @classmethod
    def validate_deal_value(cls, deal_value) -> Decimal:
        """
        Validate deal value with enhanced decimal precision validation
        Task 5.1.1: Enhanced precision validation for currency amounts
        """
        if deal_value is None:
            raise ValidationError('Deal value cannot be None')
        
        try:
            # Convert to Decimal for precision handling
            if not isinstance(deal_value, Decimal):
                decimal_value = Decimal(str(deal_value))
            else:
                decimal_value = deal_value
            
            # Task 5.1.1: Enforce exactly 2 decimal places
            # Check if the amount has more than 2 decimal places before quantizing
            if decimal_value.as_tuple().exponent < -2:
                raise ValidationError(
                    f'Deal value must have exactly 2 decimal places or fewer. '
                    f'Received: {deal_value} (has {abs(decimal_value.as_tuple().exponent)} decimal places)'
                )
            
            # Quantize to exactly 2 decimal places
            validated_value = decimal_value.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            # Validate minimum value
            if validated_value < Decimal('0.01'):
                raise ValidationError(
                    f'Deal value must be at least $0.01. Received: ${validated_value}'
                )
            
            # Validate maximum value
            if validated_value > cls.MAX_DEAL_VALUE:
                raise ValidationError(
                    f'Deal value cannot exceed ${cls.MAX_DEAL_VALUE:,.2f}. Received: ${validated_value:,.2f}'
                )
            
            # Task 5.1.1: Final precision check - ensure exactly 2 decimal places
            if validated_value.as_tuple().exponent != -2:
                validated_value = validated_value.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            return validated_value
            
        except (InvalidOperation, ValueError) as e:
            raise ValidationError(
                f'Invalid deal value format: {deal_value}. '
                f'Please provide a valid currency amount with up to 2 decimal places. Error: {str(e)}'
            )
    
    @classmethod
    def validate_payment_amount(cls, payment_amount, deal_value: Decimal = None) -> Decimal:
        """
        Validate payment amount with enhanced decimal precision validation
        Task 5.1.1: Enhanced precision validation for currency amounts
        """
        if payment_amount is None:
            raise ValidationError('Payment amount cannot be None')
        
        try:
            # Convert to Decimal for precision handling
            if not isinstance(payment_amount, Decimal):
                decimal_amount = Decimal(str(payment_amount))
            else:
                decimal_amount = payment_amount
            
            # Task 5.1.1: Enforce exactly 2 decimal places
            # Check if the amount has more than 2 decimal places before quantizing
            if decimal_amount.as_tuple().exponent < -2:
                raise ValidationError(
                    f'Payment amount must have exactly 2 decimal places or fewer. '
                    f'Received: {payment_amount} (has {abs(decimal_amount.as_tuple().exponent)} decimal places)'
                )
            
            # Quantize to exactly 2 decimal places
            validated_amount = decimal_amount.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            # Validate minimum amount
            if validated_amount < Decimal('0.01'):
                raise ValidationError(
                    f'Payment amount must be at least $0.01. Received: ${validated_amount}'
                )
            
            # Validate maximum amount
            if validated_amount > cls.MAX_DEAL_VALUE:
                raise ValidationError(
                    f'Payment amount cannot exceed ${cls.MAX_DEAL_VALUE:,.2f}. Received: ${validated_amount:,.2f}'
                )
            
            # Additional validation against deal value if provided
            if deal_value and validated_amount > deal_value:
                raise ValidationError(
                    f'Payment amount (${validated_amount:,.2f}) cannot exceed deal value (${deal_value:,.2f})'
                )
            
            # Task 5.1.1: Final precision check - ensure exactly 2 decimal places
            if validated_amount.as_tuple().exponent != -2:
                validated_amount = validated_amount.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            return validated_amount
            
        except (InvalidOperation, ValueError) as e:
            raise ValidationError(
                f'Invalid payment amount format: {payment_amount}. '
                f'Please provide a valid currency amount with up to 2 decimal places. Error: {str(e)}'
            )
    
    @classmethod
    def validate_commission_rate(cls, commission_rate) -> Decimal:
        """
        Validate commission rate percentage
        """
        return cls.validate_decimal_field(
            commission_rate,
            'commission_rate',
            max_value=cls.MAX_COMMISSION_RATE,
            min_value=Decimal('0.00'),
            precision=cls.PERCENTAGE_PRECISION
        )
    
    @classmethod
    def validate_exchange_rate(cls, exchange_rate) -> Decimal:
        """
        Validate exchange rate
        """
        return cls.validate_decimal_field(
            exchange_rate,
            'exchange_rate',
            max_value=cls.MAX_EXCHANGE_RATE,
            min_value=Decimal('0.000001'),
            precision=cls.EXCHANGE_RATE_PRECISION
        )
    
    @classmethod
    def calculate_commission_amount(cls, sales_amount: Decimal, commission_rate: Decimal) -> Decimal:
        """
        Calculate commission amount with enhanced precision validation
        Task 5.3.1: Enhanced commission calculation precision
        """
        # Validate inputs with enhanced precision checks
        validated_sales = cls.validate_currency_field(sales_amount, 'sales_amount')
        validated_rate = cls.validate_commission_rate(commission_rate)
        
        # Perform calculation with overflow protection
        try:
            # Calculate commission: sales * (rate / 100)
            # Use high precision intermediate calculation
            rate_decimal = validated_rate / Decimal('100')
            
            # Check for potential overflow before multiplication
            max_safe_sales = cls.MAX_DEAL_VALUE / (validated_rate / Decimal('100'))
            if validated_sales > max_safe_sales:
                raise ValidationError(
                    f'Commission calculation would result in overflow. '
                    f'Maximum sales amount for {validated_rate}% commission rate is ${max_safe_sales:,.2f}'
                )
            
            commission = validated_sales * rate_decimal
            
            # Ensure exactly 2 decimal places for currency
            result = commission.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            # Final precision validation
            if result.as_tuple().exponent != -2:
                result = result.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            return result
            
        except (InvalidOperation, ValueError) as e:
            raise ValidationError(
                f'Commission calculation error: {str(e)}. '
                f'Sales amount: ${validated_sales}, Commission rate: {validated_rate}%'
            )
    
    @classmethod
    def calculate_currency_conversion(cls, amount: Decimal, exchange_rate: Decimal) -> Decimal:
        """
        Calculate currency conversion with enhanced precision validation
        Task 5.3.1: Enhanced exchange rate validation for commission calculations
        """
        # Validate inputs with enhanced precision
        validated_amount = cls.validate_currency_field(amount, 'amount')
        validated_rate = cls.validate_exchange_rate(exchange_rate)
        
        try:
            # Check for potential overflow before conversion
            if validated_amount > cls.MAX_DEAL_VALUE / validated_rate:
                raise ValidationError(
                    f'Currency conversion would result in overflow. '
                    f'Maximum amount for exchange rate {validated_rate} is ${cls.MAX_DEAL_VALUE / validated_rate:,.2f}'
                )
            
            converted_amount = validated_amount * validated_rate
            
            # Ensure exactly 2 decimal places for currency
            result = converted_amount.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            # Final precision validation
            if result.as_tuple().exponent != -2:
                result = result.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            return result
            
        except (InvalidOperation, ValueError) as e:
            raise ValidationError(
                f'Currency conversion error: {str(e)}. '
                f'Amount: ${validated_amount}, Exchange rate: {validated_rate}'
            )
    
    @classmethod
    def calculate_payment_progress(cls, total_paid: Decimal, deal_value: Decimal) -> Decimal:
        """
        Calculate payment progress percentage with enhanced accuracy
        Task 5.2.2: Enhanced payment progress calculation
        """
        validated_paid = cls.validate_decimal_field(
            total_paid, 'total_paid', precision=cls.CURRENCY_PRECISION
        )
        validated_deal_value = cls.validate_deal_value(deal_value)
        
        if validated_deal_value == 0:
            return Decimal('0.0000')
        
        # Calculate progress with high precision
        progress = (validated_paid / validated_deal_value) * Decimal('100')
        
        # Round to 4 decimal places for percentage precision
        return progress.quantize(cls.PERCENTAGE_PRECISION, rounding=ROUND_HALF_UP)
    
    @classmethod
    def calculate_comprehensive_commission(cls, sales_amount: Decimal, commission_rate: Decimal, 
                                         exchange_rate: Decimal = None, bonus: Decimal = None,
                                         penalty: Decimal = None) -> Dict[str, Any]:
        """
        Calculate comprehensive commission with all components and validation
        Task 5.3.1: Comprehensive commission calculation with precision validation
        """
        
        # Default values
        if exchange_rate is None:
            exchange_rate = Decimal('1.000000')
        if bonus is None:
            bonus = Decimal('0.00')
        if penalty is None:
            penalty = Decimal('0.00')
        
        errors = []
        warnings = []
        calculations = {}
        
        try:
            # Step 1: Validate all inputs
            validated_sales = cls.validate_currency_field(sales_amount, 'sales_amount')
            validated_rate = cls.validate_commission_rate(commission_rate)
            validated_exchange_rate = cls.validate_exchange_rate(exchange_rate)
            validated_bonus = cls.validate_currency_field(bonus, 'bonus')
            validated_penalty = cls.validate_currency_field(penalty, 'penalty')
            
            # Step 2: Calculate base commission
            base_commission = cls.calculate_commission_amount(validated_sales, validated_rate)
            calculations['base_commission'] = base_commission
            
            # Step 3: Apply exchange rate conversion
            converted_commission = cls.calculate_currency_conversion(base_commission, validated_exchange_rate)
            calculations['converted_commission'] = converted_commission
            
            # Step 4: Add bonus
            commission_with_bonus = converted_commission + validated_bonus
            calculations['commission_with_bonus'] = commission_with_bonus
            
            # Step 5: Apply penalty
            final_commission = commission_with_bonus - validated_penalty
            calculations['final_commission'] = final_commission
            
            # Step 6: Calculate additional metrics
            effective_rate = (final_commission / validated_sales * 100) if validated_sales > 0 else Decimal('0.0000')
            calculations['effective_commission_rate'] = effective_rate.quantize(cls.PERCENTAGE_PRECISION)
            
            # Convert sales amount for comparison
            converted_sales = cls.calculate_currency_conversion(validated_sales, validated_exchange_rate)
            calculations['converted_sales'] = converted_sales
            
            # Calculate commission as percentage of converted sales
            converted_rate = (converted_commission / converted_sales * 100) if converted_sales > 0 else Decimal('0.0000')
            calculations['converted_commission_rate'] = converted_rate.quantize(cls.PERCENTAGE_PRECISION)
            
            # Step 7: Validation checks
            if final_commission < Decimal('0.00'):
                warnings.append(
                    f'Final commission is negative (${final_commission:.2f}). '
                    f'Penalty (${validated_penalty:.2f}) exceeds commission with bonus (${commission_with_bonus:.2f})'
                )
            
            if validated_penalty > commission_with_bonus:
                warnings.append(
                    f'Penalty amount (${validated_penalty:.2f}) exceeds total commission with bonus (${commission_with_bonus:.2f})'
                )
            
            if effective_rate > validated_rate * Decimal('2'):
                warnings.append(
                    f'Effective commission rate ({effective_rate:.4f}%) is more than double the base rate ({validated_rate:.4f}%)'
                )
            
            # Check for precision consistency
            precision_checks = [
                base_commission.as_tuple().exponent == -2,
                converted_commission.as_tuple().exponent == -2,
                final_commission.as_tuple().exponent == -2
            ]
            
            if not all(precision_checks):
                warnings.append('Some commission calculations may have precision inconsistencies')
            
            return {
                'success': True,
                'calculations': calculations,
                'inputs': {
                    'sales_amount': validated_sales,
                    'commission_rate': validated_rate,
                    'exchange_rate': validated_exchange_rate,
                    'bonus': validated_bonus,
                    'penalty': validated_penalty
                },
                'warnings': warnings,
                'errors': errors,
                'summary': {
                    'final_commission': final_commission,
                    'effective_rate': effective_rate,
                    'total_adjustments': validated_bonus - validated_penalty,
                    'commission_ratio': (final_commission / validated_sales) if validated_sales > 0 else Decimal('0')
                }
            }
            
        except ValidationError as e:
            errors.append(str(e))
            return {
                'success': False,
                'calculations': calculations,
                'warnings': warnings,
                'errors': errors
            }
        except Exception as e:
            errors.append(f'Unexpected error in commission calculation: {str(e)}')
            return {
                'success': False,
                'calculations': calculations,
                'warnings': warnings,
                'errors': errors
            }
    
    @classmethod
    def validate_commission_calculation_accuracy(cls, test_cases: List[Dict]) -> Dict[str, Any]:
        """
        Validate commission calculation accuracy across multiple test cases
        Task 5.3.1: Commission calculation accuracy tests
        """
        
        results = []
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        accuracy_errors = []
        
        for i, test_case in enumerate(test_cases):
            total_tests += 1
            test_result = {
                'test_case': i + 1,
                'inputs': test_case,
                'success': False,
                'calculated_result': None,
                'expected_result': test_case.get('expected_result'),
                'accuracy_check': False,
                'errors': []
            }
            
            try:
                # Calculate commission using our method
                calculated = cls.calculate_comprehensive_commission(
                    test_case.get('sales_amount', Decimal('0')),
                    test_case.get('commission_rate', Decimal('0')),
                    test_case.get('exchange_rate', Decimal('1')),
                    test_case.get('bonus', Decimal('0')),
                    test_case.get('penalty', Decimal('0'))
                )
                
                test_result['success'] = calculated['success']
                test_result['calculated_result'] = calculated.get('summary', {}).get('final_commission')
                
                # Check accuracy if expected result provided
                if test_case.get('expected_result') is not None:
                    expected = Decimal(str(test_case['expected_result']))
                    calculated_amount = test_result['calculated_result']
                    
                    if calculated_amount is not None:
                        # Allow small tolerance for floating point precision
                        tolerance = Decimal('0.01')  # 1 cent tolerance
                        difference = abs(calculated_amount - expected)
                        
                        if difference <= tolerance:
                            test_result['accuracy_check'] = True
                            passed_tests += 1
                        else:
                            failed_tests += 1
                            test_result['errors'].append(
                                f'Accuracy check failed. Expected: ${expected:.2f}, '
                                f'Calculated: ${calculated_amount:.2f}, Difference: ${difference:.2f}'
                            )
                            accuracy_errors.append(test_result['errors'][-1])
                    else:
                        failed_tests += 1
                        test_result['errors'].append('Calculation failed, no result to compare')
                else:
                    # No expected result, just check if calculation succeeded
                    if calculated['success']:
                        passed_tests += 1
                        test_result['accuracy_check'] = True
                
            except Exception as e:
                failed_tests += 1
                test_result['errors'].append(f'Test execution error: {str(e)}')
            
            results.append(test_result)
        
        # Calculate accuracy statistics
        accuracy_rate = (passed_tests / max(total_tests, 1)) * 100
        
        return {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'accuracy_rate': Decimal(str(accuracy_rate)).quantize(Decimal('0.01')),
            'detailed_results': results,
            'accuracy_errors': accuracy_errors,
            'summary': {
                'all_tests_passed': failed_tests == 0,
                'accuracy_acceptable': accuracy_rate >= 95.0,  # 95% threshold
                'precision_consistent': all(
                    result.get('calculated_result') is None or 
                    result['calculated_result'].as_tuple().exponent == -2
                    for result in results if result.get('calculated_result')
                )
            }
        }
    
    @classmethod
    def validate_payment_status_transition(cls, current_status: str, new_status: str, 
                                         payment_data: Dict) -> Dict[str, Any]:
        """
        Validate payment status transitions according to business rules
        Task 5.2.2: Payment status transition validation
        """
        
        # Define valid payment statuses
        VALID_STATUSES = {
            'pending', 'partial_payment', 'fully_paid', 'overpaid', 'refunded', 'cancelled'
        }
        
        # Define allowed transitions
        ALLOWED_TRANSITIONS = {
            'pending': {'partial_payment', 'fully_paid', 'overpaid', 'cancelled'},
            'partial_payment': {'fully_paid', 'overpaid', 'refunded', 'cancelled'},
            'fully_paid': {'overpaid', 'refunded'},
            'overpaid': {'refunded'},
            'refunded': {'pending', 'partial_payment'},  # Can restart after refund
            'cancelled': {'pending'}  # Can restart cancelled deals
        }
        
        errors = []
        warnings = []
        
        # Validate status values
        if current_status not in VALID_STATUSES:
            errors.append(f'Invalid current status: {current_status}')
        
        if new_status not in VALID_STATUSES:
            errors.append(f'Invalid new status: {new_status}')
        
        if errors:
            return {
                'valid_transition': False,
                'errors': errors,
                'warnings': warnings,
                'recommended_status': current_status
            }
        
        # Check if transition is allowed
        allowed_next_statuses = ALLOWED_TRANSITIONS.get(current_status, set())
        
        if new_status not in allowed_next_statuses:
            errors.append(
                f'Invalid transition from {current_status} to {new_status}. '
                f'Allowed transitions: {sorted(allowed_next_statuses)}'
            )
        
        # Validate transition against payment data
        deal_value = payment_data.get('deal_value', Decimal('0'))
        total_payments = payment_data.get('total_payments', Decimal('0'))
        
        if deal_value and total_payments:
            payment_ratio = total_payments / deal_value
            
            # Determine correct status based on payment data
            if total_payments == Decimal('0'):
                recommended_status = 'pending'
            elif payment_ratio < Decimal('1'):
                recommended_status = 'partial_payment'
            elif abs(payment_ratio - Decimal('1')) <= Decimal('0.01'):
                recommended_status = 'fully_paid'
            else:
                recommended_status = 'overpaid'
            
            # Check if new status matches payment data
            if new_status != recommended_status:
                if new_status in ['refunded', 'cancelled']:
                    # These are administrative statuses that override payment status
                    pass
                else:
                    warnings.append(
                        f'New status {new_status} may not match payment data. '
                        f'Based on payments, status should be {recommended_status}'
                    )
        
        return {
            'valid_transition': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'recommended_status': payment_data.get('recommended_status', new_status),
            'transition_allowed': new_status in allowed_next_statuses,
            'payment_data_consistent': len(warnings) == 0
        }
    
    @classmethod
    def calculate_payment_workflow_state(cls, deal_value: Decimal, payments: List[Dict], 
                                       current_status: str = None) -> Dict[str, Any]:
        """
        Calculate comprehensive payment workflow state
        Task 5.2.2: Payment workflow state machine
        """
        
        # Get payment consistency data
        payment_consistency = cls.validate_payment_consistency(deal_value, payments)
        
        # Determine workflow state based on payment data
        total_payments = payment_consistency['total_payments']
        overpayment = payment_consistency['overpayment']
        
        # Calculate payment ratio
        payment_ratio = total_payments / deal_value if deal_value > 0 else Decimal('0')
        
        # Determine current workflow state
        workflow_states = []
        
        if total_payments == Decimal('0.00'):
            workflow_states.append({
                'state': 'awaiting_first_payment',
                'description': 'No payments received yet',
                'progress': Decimal('0.0000'),
                'actions': ['record_payment', 'cancel_deal']
            })
        
        elif payment_ratio < Decimal('0.25'):
            workflow_states.append({
                'state': 'initial_payment_received',
                'description': 'Less than 25% paid',
                'progress': payment_consistency['payment_progress'],
                'actions': ['record_additional_payment', 'send_reminder']
            })
        
        elif payment_ratio < Decimal('0.75'):
            workflow_states.append({
                'state': 'substantial_payment_received',
                'description': 'Between 25% and 75% paid',
                'progress': payment_consistency['payment_progress'],
                'actions': ['record_final_payment', 'follow_up']
            })
        
        elif payment_ratio < Decimal('1.00'):
            workflow_states.append({
                'state': 'near_completion',
                'description': 'More than 75% paid, awaiting final payment',
                'progress': payment_consistency['payment_progress'],
                'actions': ['record_final_payment', 'prepare_completion']
            })
        
        elif abs(payment_ratio - Decimal('1.00')) <= Decimal('0.01'):
            workflow_states.append({
                'state': 'completed',
                'description': 'Deal fully paid (within 1% tolerance)',
                'progress': payment_consistency['payment_progress'],
                'actions': ['mark_complete', 'generate_receipt']
            })
        
        else:  # overpaid
            workflow_states.append({
                'state': 'overpaid',
                'description': f'Deal overpaid by ${overpayment:.2f}',
                'progress': payment_consistency['payment_progress'],
                'actions': ['issue_refund', 'adjust_deal_value', 'review_payments']
            })
        
        # Add administrative states if applicable
        if current_status in ['refunded', 'cancelled']:
            workflow_states.append({
                'state': current_status,
                'description': f'Deal has been {current_status}',
                'progress': payment_consistency['payment_progress'],
                'actions': ['review_status', 'reactivate'] if current_status == 'cancelled' else ['record_refund_completion']
            })
        
        # Determine next possible states
        current_state = workflow_states[0]['state'] if workflow_states else 'unknown'
        next_states = cls._get_next_workflow_states(current_state, payment_ratio, overpayment)
        
        return {
            'current_states': workflow_states,
            'primary_state': current_state,
            'payment_ratio': payment_ratio,
            'next_possible_states': next_states,
            'payment_consistency': payment_consistency,
            'workflow_completion': min(payment_ratio * 100, Decimal('100.00')),
            'state_transition_history': cls._generate_state_transition_log(payments),
            'recommended_actions': workflow_states[0]['actions'] if workflow_states else []
        }
    
    @classmethod
    def _get_next_workflow_states(cls, current_state: str, payment_ratio: Decimal, 
                                overpayment: Decimal) -> List[Dict[str, str]]:
        """Get possible next workflow states"""
        
        next_states = []
        
        if current_state == 'awaiting_first_payment':
            next_states = [
                {'state': 'initial_payment_received', 'trigger': 'first_payment'},
                {'state': 'cancelled', 'trigger': 'administrative_cancellation'}
            ]
        
        elif current_state == 'initial_payment_received':
            next_states = [
                {'state': 'substantial_payment_received', 'trigger': 'additional_payment'},
                {'state': 'completed', 'trigger': 'final_payment'},
                {'state': 'overpaid', 'trigger': 'excess_payment'}
            ]
        
        elif current_state == 'substantial_payment_received':
            next_states = [
                {'state': 'near_completion', 'trigger': 'additional_payment'},
                {'state': 'completed', 'trigger': 'final_payment'},
                {'state': 'overpaid', 'trigger': 'excess_payment'}
            ]
        
        elif current_state == 'near_completion':
            next_states = [
                {'state': 'completed', 'trigger': 'final_payment'},
                {'state': 'overpaid', 'trigger': 'excess_payment'}
            ]
        
        elif current_state == 'completed':
            next_states = [
                {'state': 'overpaid', 'trigger': 'additional_payment'},
                {'state': 'refunded', 'trigger': 'refund_process'}
            ]
        
        elif current_state == 'overpaid':
            next_states = [
                {'state': 'completed', 'trigger': 'refund_excess'},
                {'state': 'refunded', 'trigger': 'full_refund'}
            ]
        
        return next_states
    
    @classmethod
    def _generate_state_transition_log(cls, payments: List[Dict]) -> List[Dict[str, Any]]:
        """Generate a log of state transitions based on payment history"""
        
        transitions = []
        cumulative_amount = Decimal('0.00')
        
        for i, payment in enumerate(payments):
            if payment.get('valid', True):
                amount = payment.get('amount', Decimal('0.00'))
                cumulative_amount += amount
                
                transitions.append({
                    'payment_index': i,
                    'payment_amount': amount,
                    'cumulative_amount': cumulative_amount,
                    'timestamp': payment.get('timestamp', 'unknown'),
                    'state_change': f'payment_{i+1}_recorded'
                })
        
        return transitions
    
    @classmethod
    def validate_payment_consistency(cls, deal_value: Decimal, payments: List[Dict]) -> Dict:
        """
        Validate payment consistency across multiple payments
        Task 5.2.1: Fixed overpayment logic - ensure is_fully_paid is True when total >= deal_value
        """
        validated_deal_value = cls.validate_deal_value(deal_value)
        total_payments = Decimal('0.00')
        payment_details = []
        
        for i, payment in enumerate(payments):
            try:
                amount = cls.validate_payment_amount(
                    payment.get('amount', 0),
                    validated_deal_value
                )
                total_payments += amount
                
                payment_details.append({
                    'index': i,
                    'amount': amount,
                    'valid': True,
                    'error': None
                })
                
            except ValidationError as e:
                payment_details.append({
                    'index': i,
                    'amount': Decimal('0.00'),
                    'valid': False,
                    'error': str(e)
                })
        
        # Calculate payment status
        overpayment = total_payments - validated_deal_value
        remaining_balance = validated_deal_value - total_payments
        
        # Task 5.2.1: Fix overpayment logic - deal is fully paid when total_payments >= deal_value
        is_fully_paid = total_payments >= validated_deal_value
        
        # For display purposes, show remaining balance as zero if overpaid
        display_remaining_balance = max(remaining_balance, Decimal('0.00'))
        
        # Determine payment status with improved logic
        payment_status = 'pending'
        if is_fully_paid:
            if overpayment > cls.CURRENCY_PRECISION:
                payment_status = 'overpaid'
            else:
                payment_status = 'fully_paid'
        elif total_payments > cls.CURRENCY_PRECISION:
            payment_status = 'partially_paid'
        
        # Task 5.2.1: Enhanced overpayment validation scenarios
        overpayment_warnings = []
        if overpayment > cls.CURRENCY_PRECISION:
            overpayment_warnings.append(
                f'Deal is overpaid by ${overpayment:.2f}. Total payments (${total_payments:.2f}) '
                f'exceed deal value (${validated_deal_value:.2f})'
            )
            
            # Additional overpayment checks
            overpayment_percentage = (overpayment / validated_deal_value) * 100
            if overpayment_percentage > 10:  # More than 10% overpayment
                overpayment_warnings.append(
                    f'Significant overpayment detected: {overpayment_percentage:.1f}% above deal value. '
                    f'Please review payment records.'
                )
            elif overpayment_percentage > 5:  # More than 5% overpayment
                overpayment_warnings.append(
                    f'Notable overpayment: {overpayment_percentage:.1f}% above deal value. '
                    f'Consider issuing refund or adjusting deal value.'
                )
        
        return {
            'deal_value': validated_deal_value,
            'total_payments': total_payments,
            'remaining_balance': remaining_balance,
            'display_remaining_balance': display_remaining_balance,
            'overpayment': overpayment if overpayment > 0 else Decimal('0.00'),
            'is_overpaid': overpayment > cls.CURRENCY_PRECISION,
            'is_fully_paid': is_fully_paid,  # Task 5.2.1: Fixed logic
            'payment_status': payment_status,
            'overpayment_percentage': (overpayment / validated_deal_value * 100) if validated_deal_value > 0 else Decimal('0'),
            'overpayment_warnings': overpayment_warnings,
            'payment_progress': cls.calculate_payment_progress(total_payments, validated_deal_value),
            'payment_details': payment_details,
            'validation_errors': [p for p in payment_details if not p['valid']],
            # Task 5.2.1: Additional overpayment scenario data
            'scenarios': {
                'exact_payment': abs(total_payments - validated_deal_value) <= cls.CURRENCY_PRECISION,
                'underpayment': total_payments < validated_deal_value,
                'minor_overpayment': 0 < overpayment <= (validated_deal_value * Decimal('0.05')),  # ≤5%
                'significant_overpayment': overpayment > (validated_deal_value * Decimal('0.10'))  # >10%
            }
        }
    
    @classmethod
    def get_financial_integrity_report(cls, deal_queryset) -> Dict:
        """
        Generate financial integrity report for a set of deals
        """
        report = {
            'total_deals': 0,
            'total_deal_value': Decimal('0.00'),
            'total_payments': Decimal('0.00'),
            'deals_with_issues': [],
            'summary': {
                'overpaid_deals': 0,
                'underpaid_deals': 0,
                'fully_paid_deals': 0,
                'zero_value_deals': 0,
                'invalid_amounts': 0
            }
        }
        
        for deal in deal_queryset:
            report['total_deals'] += 1
            
            try:
                # Validate deal value
                deal_value = cls.validate_deal_value(deal.deal_value)
                report['total_deal_value'] += deal_value
                
                # Get payment information
                payments = []
                for payment in deal.payments.all():
                    payments.append({'amount': payment.received_amount})
                
                # Validate payment consistency
                payment_analysis = cls.validate_payment_consistency(deal_value, payments)
                report['total_payments'] += payment_analysis['total_payments']
                
                # Categorize deals
                if payment_analysis['is_overpaid']:
                    report['summary']['overpaid_deals'] += 1
                    report['deals_with_issues'].append({
                        'deal_id': str(deal.id),
                        'deal_value': deal_value,
                        'issue': 'overpaid',
                        'overpayment': payment_analysis['overpayment']
                    })
                elif payment_analysis['is_fully_paid']:
                    report['summary']['fully_paid_deals'] += 1
                elif payment_analysis['remaining_balance'] > 0:
                    report['summary']['underpaid_deals'] += 1
                
                if deal_value == 0:
                    report['summary']['zero_value_deals'] += 1
                    report['deals_with_issues'].append({
                        'deal_id': str(deal.id),
                        'issue': 'zero_value'
                    })
                
            except ValidationError as e:
                report['summary']['invalid_amounts'] += 1
                report['deals_with_issues'].append({
                    'deal_id': str(deal.id),
                    'issue': 'validation_error',
                    'error': str(e)
                })
        
        # Calculate summary percentages
        if report['total_deals'] > 0:
            report['summary']['overpaid_percentage'] = float(
                (Decimal(report['summary']['overpaid_deals']) / Decimal(report['total_deals'])) * 100
            )
            report['summary']['fully_paid_percentage'] = float(
                (Decimal(report['summary']['fully_paid_deals']) / Decimal(report['total_deals'])) * 100
            )
        
        return report
    
    @classmethod
    def fix_financial_inconsistencies(cls, deal_queryset, dry_run: bool = True) -> Dict:
        """
        Attempt to fix financial inconsistencies in deals
        """
        fixes_applied = []
        failed_fixes = []
        
        for deal in deal_queryset:
            try:
                with transaction.atomic():
                    # Validate and fix deal value
                    original_value = deal.deal_value
                    validated_value = cls.validate_deal_value(deal.deal_value)
                    
                    if original_value != validated_value:
                        if not dry_run:
                            deal.deal_value = validated_value
                            deal.save()
                        
                        fixes_applied.append({
                            'deal_id': str(deal.id),
                            'field': 'deal_value',
                            'old_value': float(original_value),
                            'new_value': float(validated_value),
                            'fix_type': 'precision_correction'
                        })
                    
                    # Validate payments
                    for payment in deal.payments.all():
                        original_amount = payment.received_amount
                        try:
                            validated_amount = cls.validate_payment_amount(
                                payment.received_amount,
                                validated_value
                            )
                            
                            if original_amount != validated_amount:
                                if not dry_run:
                                    payment.received_amount = validated_amount
                                    payment.save()
                                
                                fixes_applied.append({
                                    'deal_id': str(deal.id),
                                    'payment_id': payment.id,
                                    'field': 'received_amount',
                                    'old_value': float(original_amount),
                                    'new_value': float(validated_amount),
                                    'fix_type': 'precision_correction'
                                })
                        
                        except ValidationError as e:
                            failed_fixes.append({
                                'deal_id': str(deal.id),
                                'payment_id': payment.id,
                                'error': str(e)
                            })
            
            except Exception as e:
                failed_fixes.append({
                    'deal_id': str(deal.id),
                    'error': str(e)
                })
        
        return {
            'dry_run': dry_run,
            'fixes_applied': fixes_applied,
            'failed_fixes': failed_fixes,
            'summary': {
                'total_fixes': len(fixes_applied),
                'failed_fixes': len(failed_fixes)
            }
        }


class FinancialValidationMixin:
    """
    Mixin to add financial validation methods to Django models
    """
    
    def validate_financial_fields(self):
        """
        Validate all financial fields in the model
        """
        errors = {}
        
        # Validate deal_value if present
        if hasattr(self, 'deal_value') and self.deal_value is not None:
            try:
                self.deal_value = FinancialFieldOptimizer.validate_deal_value(self.deal_value)
            except ValidationError as e:
                errors['deal_value'] = e.message
        
        # Validate received_amount if present
        if hasattr(self, 'received_amount') and self.received_amount is not None:
            try:
                deal_value = getattr(self.deal, 'deal_value', None) if hasattr(self, 'deal') else None
                self.received_amount = FinancialFieldOptimizer.validate_payment_amount(
                    self.received_amount, deal_value
                )
            except ValidationError as e:
                errors['received_amount'] = e.message
        
        # Validate commission_rate if present
        if hasattr(self, 'commission_rate') and self.commission_rate is not None:
            try:
                self.commission_rate = FinancialFieldOptimizer.validate_commission_rate(self.commission_rate)
            except ValidationError as e:
                errors['commission_rate'] = e.message
        
        # Validate exchange_rate if present
        if hasattr(self, 'exchange_rate') and self.exchange_rate is not None:
            try:
                self.exchange_rate = FinancialFieldOptimizer.validate_exchange_rate(self.exchange_rate)
            except ValidationError as e:
                errors['exchange_rate'] = e.message
        
        if errors:
            raise ValidationError(errors)
    
    def get_financial_summary(self):
        """
        Get financial summary for the model instance
        """
        summary = {}
        
        if hasattr(self, 'deal_value'):
            summary['deal_value'] = float(self.deal_value or 0)
        
        if hasattr(self, 'received_amount'):
            summary['received_amount'] = float(self.received_amount or 0)
        
        if hasattr(self, 'commission_rate'):
            summary['commission_rate'] = float(self.commission_rate or 0)
        
        if hasattr(self, 'exchange_rate'):
            summary['exchange_rate'] = float(self.exchange_rate or 1)
        
        return summary