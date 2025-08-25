"""
Payment Service - Task 2.1.3

Business logic service for payment operations and financial calculations.
Implements payment processing, decimal precision validation, and overpayment logic fixes.
"""

from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, List, Optional, Any, Tuple
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.models import Sum, Count, Q, F

from .base_service import BaseService, ServiceResult
from deals.models import Deal, Payment
from apps.deals.financial_optimizer import FinancialFieldOptimizer
import logging

logger = logging.getLogger(__name__)


class PaymentService(BaseService):
    """
    Service for managing payment operations and financial calculations
    Task 2.1.3: Payment processing logic extraction and overpayment fixes
    """
    
    # Payment status definitions
    PAYMENT_STATUSES = {
        'pending': 'Payment created but not verified',
        'verified': 'Payment verified and confirmed',
        'rejected': 'Payment rejected or failed',
        'cancelled': 'Payment cancelled by user'
    }
    
    def create_payment(self, payment_data: Dict[str, Any]) -> ServiceResult:
        """
        Create a new payment with enhanced financial validation
        Task 2.1.3: Payment creation with decimal precision validation
        """
        try:
            # Validate payment data
            validation_result = self._validate_payment_data(payment_data)
            if not validation_result.success:
                return validation_result
            
            # Get and validate deal
            deal_result = self._validate_deal_access(payment_data['deal_id'])
            if not deal_result.success:
                return deal_result
            deal = deal_result.data['deal']
            
            # Validate payment amount precision (Task 5.1.1)
            try:
                validated_amount = FinancialFieldOptimizer.validate_payment_amount(
                    payment_data['payment_amount'],
                    deal.deal_value
                )
            except ValidationError as e:
                return self.create_error_result(f"Payment amount validation failed: {str(e)}")
            
            # Create payment with atomic transaction
            with transaction.atomic():
                payment = Payment.objects.create(
                    deal=deal,
                    payment_amount=validated_amount,
                    payment_date=payment_data.get('payment_date', timezone.now().date()),
                    payment_method=payment_data.get('payment_method', 'bank_transfer'),
                    payment_status='pending',
                    created_by=self.user,
                    payment_notes=payment_data.get('notes', '')
                )
                
                # Update deal payment status and check for overpayment (Task 5.2.1)
                self._update_deal_payment_status(deal)
                
                # Log payment creation
                logger.info(f"Payment created: ${validated_amount} for deal {deal.deal_id} by {self.user.email}")
                
                return self.create_result(
                    success=True,
                    data={
                        'payment_id': payment.id,
                        'deal_id': deal.id,
                        'amount': float(validated_amount),
                        'status': payment.payment_status,
                        'deal_payment_status': deal.payment_status
                    }
                )
                
        except Exception as e:
            logger.error(f"Error creating payment: {str(e)}")
            return self.create_error_result(f"Failed to create payment: {str(e)}")
    
    def verify_payment(self, payment_id: int, verification_notes: str = None) -> ServiceResult:
        """
        Verify a payment and update deal status with overpayment logic fix
        Task 5.2.1: Fix overpayment logic in payment consistency validation
        """
        try:
            payment = Payment.objects.get(id=payment_id)
            # Check organization access through deal
            if payment.deal.organization != self.organization:
                return self.create_error_result("Payment not found or access denied")
        except Payment.DoesNotExist:
            return self.create_error_result("Payment not found")
        
        if payment.payment_status != 'pending':
            return self.create_error_result(f"Payment is already {payment.payment_status}")
        
        try:
            with transaction.atomic():
                payment.payment_status = 'verified'
                payment.verified_by = self.user
                payment.verified_at = timezone.now()
                if verification_notes:
                    payment.payment_notes += f" | Verification: {verification_notes}"
                payment.save()
                
                # Update deal payment status with fixed overpayment logic (Task 5.2.1)
                deal = payment.deal
                self._update_deal_payment_status(deal)
                
                # Get payment consistency status
                consistency_result = self.validate_payment_consistency(deal.id)
                
                # Log verification
                logger.info(f"Payment verified: ${payment.payment_amount} for deal {deal.deal_id} by {self.user.email}")
                
                return self.create_result(
                    success=True,
                    data={
                        'payment_id': payment.id,
                        'deal_id': deal.id,
                        'payment_status': payment.payment_status,
                        'deal_payment_status': deal.payment_status,
                        'is_fully_paid': consistency_result.data.get('is_fully_paid', False),
                        'total_payments': consistency_result.data.get('total_payments', 0),
                        'remaining_balance': consistency_result.data.get('remaining_balance', 0)
                    }
                )
                
        except Exception as e:
            logger.error(f"Error verifying payment: {str(e)}")
            return self.create_error_result(f"Failed to verify payment: {str(e)}")
    
    def validate_payment_consistency(self, deal_id: int) -> ServiceResult:
        """
        Validate payment consistency with enhanced overpayment logic
        Task 5.2.1: Enhanced payment status calculation with overpayment fix
        """
        try:
            deal = Deal.objects.get(id=deal_id, organization=self.organization)
        except Deal.DoesNotExist:
            return self.create_error_result("Deal not found or access denied")
        
        try:
            # Calculate total verified payments
            total_payments = deal.payments.filter(
                payment_status='verified'
            ).aggregate(total=Sum('payment_amount'))['total'] or Decimal('0.00')
            
            # Calculate remaining balance
            remaining_balance = deal.deal_value - total_payments
            
            # Task 5.2.1: Fixed overpayment logic - is_fully_paid should be True when total >= deal_value
            is_fully_paid = total_payments >= deal.deal_value
            
            # Determine payment status
            payment_progress = Decimal('0.00')
            if deal.deal_value > 0:
                payment_progress = (total_payments / deal.deal_value).quantize(
                    Decimal('0.01'), rounding=ROUND_HALF_UP
                )
            
            # Enhanced payment status calculation
            if total_payments == 0:
                payment_status = 'not_started'
            elif total_payments < deal.deal_value:
                payment_status = 'partial'
            elif total_payments == deal.deal_value:
                payment_status = 'full'
            else:  # total_payments > deal.deal_value
                payment_status = 'overpaid'
            
            return self.create_result(
                success=True,
                data={
                    'deal_id': deal.id,
                    'total_payments': float(total_payments),
                    'deal_value': float(deal.deal_value),
                    'remaining_balance': float(remaining_balance),
                    'payment_progress': float(payment_progress * 100),
                    'is_fully_paid': is_fully_paid,  # Task 5.2.1: Fixed logic
                    'payment_status': payment_status,
                    'payment_count': deal.payments.filter(payment_status='verified').count()
                }
            )
            
        except Exception as e:
            logger.error(f"Error validating payment consistency: {str(e)}")
            return self.create_error_result(f"Failed to validate consistency: {str(e)}")
    
    def calculate_commission(self, deal_id: int, commission_rate: Decimal) -> ServiceResult:
        """
        Calculate commission with precision validation
        Task 5.3.1: Commission calculation precision validation
        """
        try:
            deal = Deal.objects.get(id=deal_id, organization=self.organization)
        except Deal.DoesNotExist:
            return self.create_error_result("Deal not found or access denied")
        
        try:
            # Validate commission rate
            if not (Decimal('0.00') <= commission_rate <= Decimal('100.00')):
                return self.create_error_result("Commission rate must be between 0% and 100%")
            
            # Calculate commission with precision
            commission_decimal = commission_rate / Decimal('100')  # Convert percentage to decimal
            commission_amount = (deal.deal_value * commission_decimal).quantize(
                Decimal('0.01'), rounding=ROUND_HALF_UP
            )
            
            # Calculate net amount after commission
            net_amount = deal.deal_value - commission_amount
            
            return self.create_result(
                success=True,
                data={
                    'deal_id': deal.id,
                    'deal_value': float(deal.deal_value),
                    'commission_rate': float(commission_rate),
                    'commission_amount': float(commission_amount),
                    'net_amount': float(net_amount),
                    'calculation_date': timezone.now().isoformat()
                }
            )
            
        except Exception as e:
            logger.error(f"Error calculating commission: {str(e)}")
            return self.create_error_result(f"Failed to calculate commission: {str(e)}")
    
    def get_payment_analytics(self, filters: Dict[str, Any] = None) -> ServiceResult:
        """
        Get payment analytics and statistics
        Task 2.1.3: Payment analytics
        """
        try:
            # Base queryset for organization (through deals)
            queryset = Payment.objects.filter(deal__organization=self.organization)
            
            # Apply filters
            if filters:
                if filters.get('status'):
                    queryset = queryset.filter(payment_status=filters['status'])
                if filters.get('date_from'):
                    queryset = queryset.filter(payment_date__gte=filters['date_from'])
                if filters.get('date_to'):
                    queryset = queryset.filter(payment_date__lte=filters['date_to'])
                if filters.get('deal_id'):
                    queryset = queryset.filter(deal_id=filters['deal_id'])
            
            # Calculate analytics
            total_payments = queryset.count()
            total_amount = queryset.filter(
                payment_status='verified'
            ).aggregate(total=Sum('payment_amount'))['total'] or Decimal('0.00')
            
            # Status breakdown
            status_breakdown = queryset.values('payment_status').annotate(
                count=Count('id'),
                amount=Sum('payment_amount')
            ).order_by('payment_status')
            
            # Method breakdown
            method_breakdown = queryset.values('payment_method').annotate(
                count=Count('id'),
                amount=Sum('payment_amount')
            ).order_by('payment_method')
            
            # Recent payments
            recent_payments = queryset.order_by('-created_at')[:10].values(
                'id', 'payment_amount', 'payment_status', 'payment_date', 'deal__deal_name'
            )
            
            return self.create_result(
                success=True,
                data={
                    'total_payments': total_payments,
                    'total_verified_amount': float(total_amount),
                    'status_breakdown': list(status_breakdown),
                    'method_breakdown': list(method_breakdown),
                    'recent_payments': list(recent_payments),
                    'average_payment': float(total_amount / total_payments) if total_payments > 0 else 0.0
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting payment analytics: {str(e)}")
            return self.create_error_result(f"Failed to get analytics: {str(e)}")
    
    # Private helper methods
    def _validate_payment_data(self, payment_data: Dict[str, Any]) -> ServiceResult:
        """Validate payment creation data"""
        errors = []
        
        # Required fields
        required_fields = ['deal_id', 'payment_amount']
        for field in required_fields:
            if not payment_data.get(field):
                errors.append(f"Field '{field}' is required")
        
        # Payment amount validation (basic check before financial optimizer)
        if payment_data.get('payment_amount'):
            try:
                amount = Decimal(str(payment_data['payment_amount']))
                if amount <= 0:
                    errors.append("Payment amount must be greater than 0")
            except (ValueError, TypeError):
                errors.append("Payment amount must be a valid decimal number")
        
        if errors:
            return ServiceResult(success=False, errors=errors)
        return ServiceResult(success=True)
    
    def _validate_deal_access(self, deal_id: int) -> ServiceResult:
        """Validate deal exists and user has access"""
        try:
            deal = Deal.objects.get(id=deal_id, organization=self.organization)
            return ServiceResult(success=True, data={'deal': deal})
        except Deal.DoesNotExist:
            return ServiceResult(
                success=False, 
                errors=["Deal not found or access denied"]
            )
    
    def _update_deal_payment_status(self, deal: Deal):
        """
        Update deal payment status with fixed overpayment logic
        Task 5.2.1: Enhanced payment status transition validation
        """
        # Calculate total verified payments
        total_payments = deal.payments.filter(
            payment_status='verified'
        ).aggregate(total=Sum('payment_amount'))['total'] or Decimal('0.00')
        
        # Task 5.2.1: Fixed overpayment logic
        if total_payments == 0:
            deal.payment_status = 'not_started'
        elif total_payments < deal.deal_value:
            deal.payment_status = 'partial'
        elif total_payments >= deal.deal_value:  # Fixed: >= instead of ==
            deal.payment_status = 'full'  # Mark as full even if overpaid
            
            # If significantly overpaid, add a note
            if total_payments > deal.deal_value:
                overpaid_amount = total_payments - deal.deal_value
                logger.warning(f"Deal {deal.deal_id} overpaid by ${overpaid_amount}")
        
        deal.save(update_fields=['payment_status'])
