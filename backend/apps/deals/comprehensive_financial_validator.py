"""
Comprehensive Financial Validation System - Task 5.1.2

Implements currency precision validation across all models, decimal overflow protection,
and financial calculation accuracy validation.
"""

from decimal import Decimal, ROUND_HALF_UP, InvalidOperation, Overflow, DivisionByZero
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from typing import Dict, List, Optional, Any, Tuple
import logging
from dataclasses import dataclass
import re

logger = logging.getLogger('financial_validation')


@dataclass
class FinancialValidationResult:
    """Result of comprehensive financial validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    corrected_values: Dict[str, Decimal]
    validation_summary: Dict[str, Any]


class ComprehensiveFinancialValidator:
    """
    Comprehensive financial validation system
    Task 5.1.2: Complete financial validation and overflow protection
    """
    
    # Precision settings for different financial fields
    CURRENCY_PRECISION = Decimal('0.01')  # 2 decimal places
    PERCENTAGE_PRECISION = Decimal('0.0001')  # 4 decimal places
    EXCHANGE_RATE_PRECISION = Decimal('0.000001')  # 6 decimal places
    COMMISSION_PRECISION = Decimal('0.01')  # 2 decimal places for commission amounts
    
    # Overflow protection limits
    MAX_CURRENCY_VALUE = Decimal('999999999.99')  # ~1 billion
    MIN_CURRENCY_VALUE = Decimal('0.01')
    MAX_PERCENTAGE = Decimal('100.0000')
    MIN_PERCENTAGE = Decimal('0.0000')
    MAX_EXCHANGE_RATE = Decimal('10000.000000')
    MIN_EXCHANGE_RATE = Decimal('0.000001')
    
    # Financial field patterns for model validation
    CURRENCY_FIELD_PATTERNS = [
        'deal_value', 'received_amount', 'payment_amount', 'commission_amount',
        'total_amount', 'balance', 'refund_amount', 'fee_amount', 'tax_amount'
    ]
    
    PERCENTAGE_FIELD_PATTERNS = [
        'commission_rate', 'tax_rate', 'fee_rate', 'discount_rate'
    ]
    
    EXCHANGE_RATE_FIELD_PATTERNS = [
        'exchange_rate', 'conversion_rate', 'currency_rate'
    ]
    
    @classmethod
    def validate_model_financial_fields(cls, model_instance: models.Model) -> FinancialValidationResult:
        """
        Validate all financial fields in a Django model instance
        Task 5.1.2: Comprehensive model validation
        """
        
        errors = []
        warnings = []
        corrected_values = {}
        
        # Get all fields from the model
        model_fields = model_instance._meta.get_fields()
        
        for field in model_fields:
            field_name = field.name
            
            # Skip non-financial fields
            if not cls._is_financial_field(field_name):
                continue
            
            field_value = getattr(model_instance, field_name, None)
            
            # Skip None values
            if field_value is None:
                continue
            
            try:
                # Determine field type and validate accordingly
                if cls._is_currency_field(field_name):
                    validated_value = cls.validate_currency_field(field_value, field_name)
                elif cls._is_percentage_field(field_name):
                    validated_value = cls.validate_percentage_field(field_value, field_name)
                elif cls._is_exchange_rate_field(field_name):
                    validated_value = cls.validate_exchange_rate_field(field_value, field_name)
                else:
                    # Default to currency validation
                    validated_value = cls.validate_currency_field(field_value, field_name)
                
                # Check if correction was needed
                if validated_value != field_value:
                    corrected_values[field_name] = validated_value
                    warnings.append(
                        f'{field_name}: Value corrected from {field_value} to {validated_value}'
                    )
                    
            except ValidationError as e:
                errors.append(f'{field_name}: {str(e)}')
            except Exception as e:
                errors.append(f'{field_name}: Unexpected validation error - {str(e)}')
        
        # Additional business logic validations
        business_validation_result = cls._validate_business_logic(model_instance)
        errors.extend(business_validation_result.get('errors', []))
        warnings.extend(business_validation_result.get('warnings', []))
        
        # Generate validation summary
        validation_summary = {
            'model_name': model_instance.__class__.__name__,
            'total_financial_fields': len([f for f in model_fields if cls._is_financial_field(f.name)]),
            'validated_fields': len(corrected_values) + len([f for f in model_fields 
                                                           if cls._is_financial_field(f.name) 
                                                           and getattr(model_instance, f.name) is not None]),
            'corrected_fields': len(corrected_values),
            'validation_timestamp': timezone.now()
        }
        
        return FinancialValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            corrected_values=corrected_values,
            validation_summary=validation_summary
        )
    
    @classmethod
    def validate_currency_field(cls, value: Any, field_name: str) -> Decimal:
        """
        Validate currency field with comprehensive checks
        Task 5.1.2: Currency field validation with overflow protection
        """
        
        if value is None:
            return Decimal('0.00')
        
        try:
            # Convert to Decimal
            if not isinstance(value, Decimal):
                # Handle string inputs with currency symbols
                if isinstance(value, str):
                    # Remove common currency symbols and formatting
                    cleaned_value = re.sub(r'[^\d.-]', '', value.replace(',', ''))
                    decimal_value = Decimal(cleaned_value)
                else:
                    decimal_value = Decimal(str(value))
            else:
                decimal_value = value
            
            # Task 5.1.2: Decimal overflow protection
            if decimal_value > cls.MAX_CURRENCY_VALUE:
                raise ValidationError(
                    f'{field_name}: Currency value {decimal_value} exceeds maximum allowed value '
                    f'of ${cls.MAX_CURRENCY_VALUE:,.2f} (overflow protection)'
                )
            
            if decimal_value < Decimal('0') and abs(decimal_value) > cls.MAX_CURRENCY_VALUE:
                raise ValidationError(
                    f'{field_name}: Negative currency value {decimal_value} exceeds maximum allowed magnitude '
                    f'of ${cls.MAX_CURRENCY_VALUE:,.2f} (overflow protection)'
                )
            
            # Enforce exactly 2 decimal places
            if decimal_value.as_tuple().exponent < -2:
                raise ValidationError(
                    f'{field_name}: Currency value must have exactly 2 decimal places or fewer. '
                    f'Received: {value} (has {abs(decimal_value.as_tuple().exponent)} decimal places)'
                )
            
            # Quantize to currency precision
            validated_value = decimal_value.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            # Final precision check
            if validated_value.as_tuple().exponent != -2:
                validated_value = validated_value.quantize(cls.CURRENCY_PRECISION, rounding=ROUND_HALF_UP)
            
            return validated_value
            
        except (InvalidOperation, ValueError, Overflow) as e:
            raise ValidationError(
                f'{field_name}: Invalid currency format - {value}. '
                f'Please provide a valid currency amount with up to 2 decimal places. Error: {str(e)}'
            )
    
    @classmethod
    def validate_percentage_field(cls, value: Any, field_name: str) -> Decimal:
        """
        Validate percentage field with comprehensive checks
        Task 5.1.2: Percentage validation with overflow protection
        """
        
        if value is None:
            return Decimal('0.0000')
        
        try:
            # Convert to Decimal
            if not isinstance(value, Decimal):
                if isinstance(value, str):
                    # Remove percentage symbol if present
                    cleaned_value = value.replace('%', '').strip()
                    decimal_value = Decimal(cleaned_value)
                else:
                    decimal_value = Decimal(str(value))
            else:
                decimal_value = value
            
            # Task 5.1.2: Overflow protection for percentages
            if decimal_value > cls.MAX_PERCENTAGE:
                raise ValidationError(
                    f'{field_name}: Percentage value {decimal_value} exceeds maximum allowed value '
                    f'of {cls.MAX_PERCENTAGE}% (overflow protection)'
                )
            
            if decimal_value < Decimal('-100.0000'):
                raise ValidationError(
                    f'{field_name}: Percentage value {decimal_value} is below minimum allowed value '
                    f'of -100% (overflow protection)'
                )
            
            # Enforce exactly 4 decimal places for percentages
            if decimal_value.as_tuple().exponent < -4:
                raise ValidationError(
                    f'{field_name}: Percentage value must have 4 decimal places or fewer. '
                    f'Received: {value} (has {abs(decimal_value.as_tuple().exponent)} decimal places)'
                )
            
            # Quantize to percentage precision
            validated_value = decimal_value.quantize(cls.PERCENTAGE_PRECISION, rounding=ROUND_HALF_UP)
            
            return validated_value
            
        except (InvalidOperation, ValueError, Overflow) as e:
            raise ValidationError(
                f'{field_name}: Invalid percentage format - {value}. '
                f'Please provide a valid percentage with up to 4 decimal places. Error: {str(e)}'
            )
    
    @classmethod
    def validate_exchange_rate_field(cls, value: Any, field_name: str) -> Decimal:
        """
        Validate exchange rate field with comprehensive checks
        Task 5.1.2: Exchange rate validation with overflow protection
        """
        
        if value is None:
            return Decimal('1.000000')
        
        try:
            # Convert to Decimal
            if not isinstance(value, Decimal):
                decimal_value = Decimal(str(value))
            else:
                decimal_value = value
            
            # Task 5.1.2: Overflow protection for exchange rates
            if decimal_value > cls.MAX_EXCHANGE_RATE:
                raise ValidationError(
                    f'{field_name}: Exchange rate {decimal_value} exceeds maximum allowed value '
                    f'of {cls.MAX_EXCHANGE_RATE} (overflow protection)'
                )
            
            if decimal_value < cls.MIN_EXCHANGE_RATE:
                raise ValidationError(
                    f'{field_name}: Exchange rate {decimal_value} is below minimum allowed value '
                    f'of {cls.MIN_EXCHANGE_RATE} (overflow protection)'
                )
            
            # Enforce exactly 6 decimal places for exchange rates
            if decimal_value.as_tuple().exponent < -6:
                raise ValidationError(
                    f'{field_name}: Exchange rate must have 6 decimal places or fewer. '
                    f'Received: {value} (has {abs(decimal_value.as_tuple().exponent)} decimal places)'
                )
            
            # Quantize to exchange rate precision
            validated_value = decimal_value.quantize(cls.EXCHANGE_RATE_PRECISION, rounding=ROUND_HALF_UP)
            
            return validated_value
            
        except (InvalidOperation, ValueError, Overflow, DivisionByZero) as e:
            raise ValidationError(
                f'{field_name}: Invalid exchange rate format - {value}. '
                f'Please provide a valid exchange rate with up to 6 decimal places. Error: {str(e)}'
            )
    
    @classmethod
    def validate_financial_calculation(cls, calculation_type: str, operands: Dict[str, Decimal]) -> Dict[str, Any]:
        """
        Validate financial calculation accuracy and prevent overflow
        Task 5.1.2: Financial calculation accuracy validation
        """
        
        try:
            result = None
            warnings = []
            
            if calculation_type == 'commission_calculation':
                # Commission = Sales Amount × Commission Rate
                sales_amount = operands.get('sales_amount', Decimal('0'))
                commission_rate = operands.get('commission_rate', Decimal('0'))
                
                # Validate inputs
                cls.validate_currency_field(sales_amount, 'sales_amount')
                cls.validate_percentage_field(commission_rate, 'commission_rate')
                
                # Perform calculation with overflow protection
                if sales_amount * commission_rate > cls.MAX_CURRENCY_VALUE * 100:
                    raise ValidationError('Commission calculation would result in overflow')
                
                result = (sales_amount * commission_rate / 100).quantize(cls.CURRENCY_PRECISION)
                
            elif calculation_type == 'payment_total':
                # Total = Sum of all payments
                payments = operands.get('payments', [])
                
                total = Decimal('0')
                for payment in payments:
                    validated_payment = cls.validate_currency_field(payment, 'payment')
                    total += validated_payment
                    
                    # Check for overflow during addition
                    if total > cls.MAX_CURRENCY_VALUE:
                        raise ValidationError('Payment total calculation would result in overflow')
                
                result = total.quantize(cls.CURRENCY_PRECISION)
                
            elif calculation_type == 'currency_conversion':
                # Converted Amount = Original Amount × Exchange Rate
                original_amount = operands.get('original_amount', Decimal('0'))
                exchange_rate = operands.get('exchange_rate', Decimal('1'))
                
                # Validate inputs
                cls.validate_currency_field(original_amount, 'original_amount')
                cls.validate_exchange_rate_field(exchange_rate, 'exchange_rate')
                
                # Perform calculation with overflow protection
                if original_amount * exchange_rate > cls.MAX_CURRENCY_VALUE:
                    raise ValidationError('Currency conversion would result in overflow')
                
                result = (original_amount * exchange_rate).quantize(cls.CURRENCY_PRECISION)
                
            else:
                raise ValidationError(f'Unknown calculation type: {calculation_type}')
            
            return {
                'success': True,
                'result': result,
                'warnings': warnings,
                'calculation_type': calculation_type,
                'operands': operands
            }
            
        except (ValidationError, InvalidOperation, Overflow, DivisionByZero) as e:
            return {
                'success': False,
                'error': str(e),
                'calculation_type': calculation_type,
                'operands': operands
            }
    
    @classmethod
    def _is_financial_field(cls, field_name: str) -> bool:
        """Check if field name indicates a financial field"""
        
        financial_patterns = (
            cls.CURRENCY_FIELD_PATTERNS + 
            cls.PERCENTAGE_FIELD_PATTERNS + 
            cls.EXCHANGE_RATE_FIELD_PATTERNS
        )
        
        return any(pattern in field_name.lower() for pattern in financial_patterns)
    
    @classmethod
    def _is_currency_field(cls, field_name: str) -> bool:
        """Check if field name indicates a currency field"""
        return any(pattern in field_name.lower() for pattern in cls.CURRENCY_FIELD_PATTERNS)
    
    @classmethod
    def _is_percentage_field(cls, field_name: str) -> bool:
        """Check if field name indicates a percentage field"""
        return any(pattern in field_name.lower() for pattern in cls.PERCENTAGE_FIELD_PATTERNS)
    
    @classmethod
    def _is_exchange_rate_field(cls, field_name: str) -> bool:
        """Check if field name indicates an exchange rate field"""
        return any(pattern in field_name.lower() for pattern in cls.EXCHANGE_RATE_FIELD_PATTERNS)
    
    @classmethod
    def _validate_business_logic(cls, model_instance: models.Model) -> Dict[str, List[str]]:
        """
        Validate business logic for financial models
        Task 5.1.2: Business logic validation
        """
        
        errors = []
        warnings = []
        
        model_name = model_instance.__class__.__name__
        
        if model_name == 'Deal':
            # Deal-specific validations
            if hasattr(model_instance, 'deal_value') and hasattr(model_instance, 'payments'):
                deal_value = getattr(model_instance, 'deal_value', Decimal('0'))
                
                if model_instance.pk:  # Only for existing deals
                    try:
                        total_payments = sum(
                            payment.received_amount or Decimal('0') 
                            for payment in model_instance.payments.all()
                        )
                        
                        # Check for overpayment
                        if total_payments > deal_value * Decimal('1.1'):  # Allow 10% overpayment tolerance
                            warnings.append(
                                f'Total payments (${total_payments:.2f}) significantly exceed deal value (${deal_value:.2f})'
                            )
                        
                        # Check for exact payment match
                        if abs(total_payments - deal_value) < Decimal('0.01') and total_payments != deal_value:
                            warnings.append(
                                f'Payment total is very close to deal value but not exact: ${total_payments:.2f} vs ${deal_value:.2f}'
                            )
                            
                    except Exception as e:
                        warnings.append(f'Could not validate payment consistency: {str(e)}')
        
        elif model_name == 'Payment':
            # Payment-specific validations
            if hasattr(model_instance, 'received_amount') and hasattr(model_instance, 'deal'):
                payment_amount = getattr(model_instance, 'received_amount', Decimal('0'))
                deal = getattr(model_instance, 'deal', None)
                
                if deal and hasattr(deal, 'deal_value'):
                    deal_value = deal.deal_value
                    
                    # Single payment cannot exceed deal value by more than reasonable margin
                    if payment_amount > deal_value * Decimal('1.05'):  # 5% tolerance
                        errors.append(
                            f'Single payment amount (${payment_amount:.2f}) exceeds deal value (${deal_value:.2f}) by more than 5%'
                        )
        
        return {
            'errors': errors,
            'warnings': warnings
        }
    
    @classmethod
    def generate_financial_validation_report(cls, model_instances: List[models.Model]) -> Dict[str, Any]:
        """
        Generate comprehensive financial validation report
        Task 5.1.2: Validation reporting
        """
        
        total_validated = 0
        total_errors = 0
        total_warnings = 0
        total_corrections = 0
        
        validation_results = []
        
        for instance in model_instances:
            result = cls.validate_model_financial_fields(instance)
            validation_results.append(result)
            
            total_validated += 1
            total_errors += len(result.errors)
            total_warnings += len(result.warnings)
            total_corrections += len(result.corrected_values)
        
        # Calculate validation statistics
        error_rate = (total_errors / max(total_validated, 1)) * 100
        correction_rate = (total_corrections / max(total_validated, 1)) * 100
        
        return {
            'summary': {
                'total_models_validated': total_validated,
                'total_errors': total_errors,
                'total_warnings': total_warnings,
                'total_corrections': total_corrections,
                'error_rate_percentage': error_rate,
                'correction_rate_percentage': correction_rate,
                'validation_timestamp': timezone.now()
            },
            'detailed_results': validation_results,
            'recommendations': cls._generate_validation_recommendations(validation_results)
        }
    
    @classmethod
    def _generate_validation_recommendations(cls, validation_results: List[FinancialValidationResult]) -> List[str]:
        """Generate recommendations based on validation results"""
        
        recommendations = []
        
        error_count = sum(len(result.errors) for result in validation_results)
        warning_count = sum(len(result.warnings) for result in validation_results)
        correction_count = sum(len(result.corrected_values) for result in validation_results)
        
        if error_count > 0:
            recommendations.append(
                f'Critical: {error_count} validation errors detected. Immediate attention required.'
            )
        
        if warning_count > error_count * 2:
            recommendations.append(
                'High warning-to-error ratio suggests data quality issues that should be addressed.'
            )
        
        if correction_count > len(validation_results) * 0.1:
            recommendations.append(
                'More than 10% of records required corrections. Consider improving data entry validation.'
            )
        
        # Common error pattern analysis
        all_errors = []
        for result in validation_results:
            all_errors.extend(result.errors)
        
        if any('decimal places' in error.lower() for error in all_errors):
            recommendations.append(
                'Precision errors detected. Ensure all financial inputs enforce proper decimal place limits.'
            )
        
        if any('overflow' in error.lower() for error in all_errors):
            recommendations.append(
                'Overflow protection triggered. Review maximum value limits for financial fields.'
            )
        
        return recommendations


# Global validator instance
comprehensive_financial_validator = ComprehensiveFinancialValidator()

# Utility functions
def validate_model_financial_fields(model_instance: models.Model) -> FinancialValidationResult:
    """Convenience function for model validation"""
    return comprehensive_financial_validator.validate_model_financial_fields(model_instance)

def validate_financial_calculation(calculation_type: str, operands: Dict[str, Decimal]) -> Dict[str, Any]:
    """Convenience function for calculation validation"""
    return comprehensive_financial_validator.validate_financial_calculation(calculation_type, operands)
