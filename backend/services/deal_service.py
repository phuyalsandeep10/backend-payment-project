"""
Deal Service - Task 2.1.2

Business logic service for deal operations extracted from models and views.
Implements deal validation, state management, and progress tracking.
"""

from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, List, Optional, Any, Tuple
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.models import Sum, Count, Q, F

from .base_service import BaseService, ServiceResult
from deals.models import Deal, Payment
from clients.models import Client
from authentication.models import User
import logging

logger = logging.getLogger(__name__)


class DealService(BaseService):
    """
    Service for managing deal operations and business logic
    Task 2.1.2: Deal workflow logic extraction
    """
    
    # Deal status transitions
    VALID_STATUS_TRANSITIONS = {
        'pending': ['in_progress', 'cancelled'],
        'in_progress': ['completed', 'cancelled', 'pending'],
        'completed': ['verified', 'cancelled'],
        'verified': ['paid', 'cancelled'],
        'paid': ['closed'],
        'cancelled': ['pending'],  # Allow reactivation
        'closed': []  # No transitions from closed
    }
    
    # Payment status calculations
    PAYMENT_THRESHOLDS = {
        'not_started': Decimal('0.00'),
        'partial': Decimal('0.01'), 
        'full': Decimal('1.00'),  # 100% of deal value
        'overpaid': Decimal('1.01')  # More than 100%
    }
    
    def create_deal(self, deal_data: Dict[str, Any]) -> ServiceResult:
        """
        Create a new deal with validation and business logic
        Task 2.1.2: Deal creation with state management
        """
        try:
            # Validate required fields
            validation_result = self._validate_deal_data(deal_data)
            if not validation_result.success:
                return validation_result
            
            # Validate client exists and belongs to organization
            client_result = self._validate_client_access(deal_data.get('client_id'))
            if not client_result.success:
                return client_result
            
            # Create deal with atomic transaction
            with transaction.atomic():
                deal = Deal.objects.create(
                    client_id=deal_data['client_id'],
                    deal_name=deal_data['deal_name'],
                    deal_value=Decimal(str(deal_data['deal_value'])),
                    currency=deal_data.get('currency', 'USD'),
                    deal_date=deal_data.get('deal_date', timezone.now().date()),
                    due_date=deal_data.get('due_date'),
                    verification_status='pending',
                    payment_status='not_started',
                    created_by=self.user,
                    organization=self.organization
                )
                
                # Calculate initial progress
                self._update_deal_progress(deal)
                
                # Log deal creation
                logger.info(f"Deal created: {deal.deal_id} by {self.user.email}")
                
                return self.create_result(
                    success=True,
                    data={
                        'deal_id': deal.id,
                        'deal_name': deal.deal_name,
                        'status': deal.verification_status,
                        'payment_status': deal.payment_status
                    }
                )
                
        except Exception as e:
            logger.error(f"Error creating deal: {str(e)}")
            return self.create_error_result(f"Failed to create deal: {str(e)}")
    
    def update_deal_status(self, deal_id: int, new_status: str, notes: str = None) -> ServiceResult:
        """
        Update deal verification status with validation
        Task 2.1.2: Deal state management
        """
        try:
            deal = Deal.objects.get(id=deal_id, organization=self.organization)
        except Deal.DoesNotExist:
            return self.create_error_result("Deal not found or access denied")
        
        # Validate status transition
        if not self._is_valid_status_transition(deal.verification_status, new_status):
            return self.create_error_result(
                f"Invalid status transition: {deal.verification_status} -> {new_status}"
            )
        
        try:
            with transaction.atomic():
                old_status = deal.verification_status
                deal.verification_status = new_status
                deal.updated_by = self.user
                deal.save()
                
                # Update progress and payment status
                self._update_deal_progress(deal)
                
                # Log status change
                logger.info(f"Deal {deal.deal_id} status: {old_status} -> {new_status} by {self.user.email}")
                
                return self.create_result(
                    success=True,
                    data={
                        'deal_id': deal.id,
                        'old_status': old_status,
                        'new_status': new_status,
                        'progress': deal.progress_percentage
                    }
                )
                
        except Exception as e:
            logger.error(f"Error updating deal status: {str(e)}")
            return self.create_error_result(f"Failed to update status: {str(e)}")
    
    def calculate_deal_progress(self, deal_id: int) -> ServiceResult:
        """
        Calculate and update deal progress percentage
        Task 2.1.2: Progress tracking
        """
        try:
            deal = Deal.objects.get(id=deal_id, organization=self.organization)
        except Deal.DoesNotExist:
            return self.create_error_result("Deal not found or access denied")
        
        try:
            # Calculate payment progress
            total_payments = deal.payments.filter(
                payment_status='verified'
            ).aggregate(total=Sum('payment_amount'))['total'] or Decimal('0.00')
            
            payment_progress = Decimal('0.00')
            if deal.deal_value > 0:
                payment_progress = (total_payments / deal.deal_value * 100).quantize(
                    Decimal('0.01'), rounding=ROUND_HALF_UP
                )
            
            # Calculate status progress (weighted)
            status_weights = {
                'pending': 0,
                'in_progress': 25,
                'completed': 50,
                'verified': 75,
                'paid': 90,
                'closed': 100
            }
            
            status_progress = status_weights.get(deal.verification_status, 0)
            
            # Combined progress (70% status, 30% payment)
            overall_progress = (
                Decimal(str(status_progress)) * Decimal('0.7') + 
                payment_progress * Decimal('0.3')
            ).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            
            # Update deal
            deal.progress_percentage = float(overall_progress)
            deal.save(update_fields=['progress_percentage'])
            
            return self.create_result(
                success=True,
                data={
                    'deal_id': deal.id,
                    'overall_progress': float(overall_progress),
                    'payment_progress': float(payment_progress),
                    'status_progress': status_progress,
                    'total_payments': float(total_payments),
                    'deal_value': float(deal.deal_value)
                }
            )
            
        except Exception as e:
            logger.error(f"Error calculating progress: {str(e)}")
            return self.create_error_result(f"Failed to calculate progress: {str(e)}")
    
    def get_deal_analytics(self, filters: Dict[str, Any] = None) -> ServiceResult:
        """
        Get deal analytics and statistics
        Task 2.1.2: Deal analytics
        """
        try:
            # Base queryset for organization
            queryset = Deal.objects.filter(organization=self.organization)
            
            # Apply filters
            if filters:
                if filters.get('status'):
                    queryset = queryset.filter(verification_status=filters['status'])
                if filters.get('date_from'):
                    queryset = queryset.filter(deal_date__gte=filters['date_from'])
                if filters.get('date_to'):
                    queryset = queryset.filter(deal_date__lte=filters['date_to'])
            
            # Calculate analytics
            total_deals = queryset.count()
            total_value = queryset.aggregate(total=Sum('deal_value'))['total'] or Decimal('0.00')
            
            # Status breakdown
            status_breakdown = queryset.values('verification_status').annotate(
                count=Count('id'),
                value=Sum('deal_value')
            ).order_by('verification_status')
            
            # Payment status breakdown
            payment_breakdown = queryset.values('payment_status').annotate(
                count=Count('id'),
                value=Sum('deal_value')
            ).order_by('payment_status')
            
            # Top performing deals
            top_deals = queryset.order_by('-deal_value')[:10].values(
                'id', 'deal_name', 'deal_value', 'verification_status'
            )
            
            return self.create_result(
                success=True,
                data={
                    'total_deals': total_deals,
                    'total_value': float(total_value),
                    'status_breakdown': list(status_breakdown),
                    'payment_breakdown': list(payment_breakdown), 
                    'top_deals': list(top_deals),
                    'average_deal_value': float(total_value / total_deals) if total_deals > 0 else 0.0
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting analytics: {str(e)}")
            return self.create_error_result(f"Failed to get analytics: {str(e)}")
    
    # Private helper methods
    def _validate_deal_data(self, deal_data: Dict[str, Any]) -> ServiceResult:
        """Validate deal creation data"""
        errors = []
        
        # Required fields
        required_fields = ['client_id', 'deal_name', 'deal_value']
        for field in required_fields:
            if not deal_data.get(field):
                errors.append(f"Field '{field}' is required")
        
        # Deal value validation
        if deal_data.get('deal_value'):
            try:
                value = Decimal(str(deal_data['deal_value']))
                if value <= 0:
                    errors.append("Deal value must be greater than 0")
            except (ValueError, TypeError):
                errors.append("Deal value must be a valid decimal number")
        
        # Deal name validation
        if deal_data.get('deal_name') and len(deal_data['deal_name']) > 200:
            errors.append("Deal name cannot exceed 200 characters")
        
        if errors:
            return ServiceResult(success=False, errors=errors)
        return ServiceResult(success=True)
    
    def _validate_client_access(self, client_id: int) -> ServiceResult:
        """Validate client exists and user has access"""
        try:
            client = Client.objects.get(id=client_id, organization=self.organization)
            return ServiceResult(success=True, data={'client': client})
        except Client.DoesNotExist:
            return ServiceResult(
                success=False, 
                errors=["Client not found or access denied"]
            )
    
    def _is_valid_status_transition(self, current_status: str, new_status: str) -> bool:
        """Check if status transition is valid"""
        if current_status == new_status:
            return True
        return new_status in self.VALID_STATUS_TRANSITIONS.get(current_status, [])
    
    def _update_deal_progress(self, deal: Deal):
        """Update deal progress and payment status"""
        # Calculate payments
        total_payments = deal.payments.filter(
            payment_status='verified'
        ).aggregate(total=Sum('payment_amount'))['total'] or Decimal('0.00')
        
        # Update payment status
        if total_payments == 0:
            deal.payment_status = 'not_started'
        elif total_payments < deal.deal_value:
            deal.payment_status = 'partial'
        elif total_payments == deal.deal_value:
            deal.payment_status = 'full'
        else:
            deal.payment_status = 'overpaid'
        
        # Update progress percentage
        payment_progress = Decimal('0.00')
        if deal.deal_value > 0:
            payment_progress = (total_payments / deal.deal_value * 100).quantize(
                Decimal('0.01'), rounding=ROUND_HALF_UP
            )
        
        status_weights = {
            'pending': 0, 'in_progress': 25, 'completed': 50,
            'verified': 75, 'paid': 90, 'closed': 100
        }
        
        status_progress = status_weights.get(deal.verification_status, 0)
        overall_progress = (
            Decimal(str(status_progress)) * Decimal('0.7') + 
            payment_progress * Decimal('0.3')
        ).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        
        deal.progress_percentage = float(overall_progress)
        deal.save(update_fields=['payment_status', 'progress_percentage'])
