"""
Atomic Financial Operations Service
Provides thread-safe financial operations with proper locking and transaction handling
"""

from django.db import transaction, IntegrityError
from django.core.exceptions import ValidationError
from django.utils import timezone
from decimal import Decimal
from contextlib import contextmanager
import logging
import time
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger('financial_atomic')

class AtomicFinancialOperations:
    """
    Service for handling atomic financial operations with proper locking
    and race condition prevention
    """
    
    # Lock timeout settings
    LOCK_TIMEOUT = 30  # seconds
    RETRY_ATTEMPTS = 3
    RETRY_DELAY = 0.1  # seconds
    
    @classmethod
    @contextmanager
    def atomic_deal_operation(cls, deal_id, operation_type='update'):
        """
        Context manager for atomic deal operations with proper locking
        """
        from apps.deals.models import Deal
        
        max_attempts = cls.RETRY_ATTEMPTS
        attempt = 0
        
        while attempt < max_attempts:
            try:
                with transaction.atomic():
                    # Use select_for_update to lock the deal record
                    deal = Deal.objects.select_for_update(
                        nowait=False  # Wait for lock if needed
                    ).get(id=deal_id)
                    
                    logger.info(f"Acquired lock for deal {deal_id} - operation: {operation_type}")
                    
                    yield deal
                    
                    logger.info(f"Released lock for deal {deal_id} - operation: {operation_type}")
                    return
                    
            except IntegrityError as e:
                attempt += 1
                if attempt >= max_attempts:
                    logger.error(f"Failed to acquire lock for deal {deal_id} after {max_attempts} attempts")
                    raise ValidationError(f"Unable to process deal operation due to concurrent access: {str(e)}")
                
                logger.warning(f"Lock contention for deal {deal_id}, attempt {attempt}/{max_attempts}")
                time.sleep(cls.RETRY_DELAY * attempt)  # Exponential backoff
                
            except Exception as e:
                logger.error(f"Atomic deal operation failed for deal {deal_id}: {str(e)}")
                raise
    
    @classmethod
    @contextmanager
    def atomic_commission_operation(cls, commission_id, operation_type='update'):
        """
        Context manager for atomic commission operations with proper locking
        """
        from commission.models import Commission
        
        max_attempts = cls.RETRY_ATTEMPTS
        attempt = 0
        
        while attempt < max_attempts:
            try:
                with transaction.atomic():
                    # Use select_for_update to lock the commission record
                    commission = Commission.objects.select_for_update(
                        nowait=False
                    ).get(id=commission_id)
                    
                    logger.info(f"Acquired lock for commission {commission_id} - operation: {operation_type}")
                    
                    yield commission
                    
                    logger.info(f"Released lock for commission {commission_id} - operation: {operation_type}")
                    return
                    
            except IntegrityError as e:
                attempt += 1
                if attempt >= max_attempts:
                    logger.error(f"Failed to acquire lock for commission {commission_id} after {max_attempts} attempts")
                    raise ValidationError(f"Unable to process commission operation due to concurrent access: {str(e)}")
                
                logger.warning(f"Lock contention for commission {commission_id}, attempt {attempt}/{max_attempts}")
                time.sleep(cls.RETRY_DELAY * attempt)
                
            except Exception as e:
                logger.error(f"Atomic commission operation failed for commission {commission_id}: {str(e)}")
                raise
    
    @classmethod
    def atomic_deal_status_change(cls, deal_id: str, new_verification_status: str = None, 
                                 new_payment_status: str = None, user=None) -> Dict:
        """
        Atomically change deal status with proper validation and audit trail
        """
        from apps.deals.models import Deal
        from core_config.models import AuditTrail
        
        with cls.atomic_deal_operation(deal_id, 'status_change') as deal:
            changes = {}
            old_values = {
                'verification_status': deal.verification_status,
                'payment_status': deal.payment_status,
                'updated_at': deal.updated_at
            }
            
            # Validate and apply verification status change
            if new_verification_status and new_verification_status != deal.verification_status:
                deal.validate_verification_status_transition(new_verification_status)
                deal.verification_status = new_verification_status
                changes['verification_status'] = {
                    'old': old_values['verification_status'],
                    'new': new_verification_status
                }
            
            # Validate and apply payment status change
            if new_payment_status and new_payment_status != deal.payment_status:
                deal.validate_payment_status_transition(new_payment_status)
                deal.payment_status = new_payment_status
                changes['payment_status'] = {
                    'old': old_values['payment_status'],
                    'new': new_payment_status
                }
            
            # Update the deal if there are changes
            if changes:
                deal.updated_by = user
                deal.save()
                
                # Create audit trail
                try:
                    AuditTrail.objects.create(
                        table_name='deals_deal',
                        record_id=str(deal.id),
                        action='STATUS_CHANGE',
                        old_values=old_values,
                        new_values={
                            'verification_status': deal.verification_status,
                            'payment_status': deal.payment_status,
                            'updated_at': deal.updated_at
                        },
                        user=user,
                        changes_summary=changes
                    )
                except Exception as e:
                    logger.error(f"Failed to create audit trail for deal {deal_id}: {str(e)}")
                
                logger.info(f"Deal {deal_id} status changed by {user.email if user else 'system'}: {changes}")
            
            return {
                'deal_id': str(deal.id),
                'changes': changes,
                'current_status': {
                    'verification_status': deal.verification_status,
                    'payment_status': deal.payment_status
                },
                'updated_at': deal.updated_at.isoformat()
            }
    
    @classmethod
    def atomic_payment_creation(cls, deal_id: str, payment_data: Dict, user=None) -> Dict:
        """
        Atomically create a payment with proper deal locking and validation
        """
        from apps.deals.models import Deal, Payment
        from core_config.models import AuditTrail
        
        with cls.atomic_deal_operation(deal_id, 'payment_creation') as deal:
            # Validate payment amount against deal
            payment_amount = Decimal(str(payment_data.get('received_amount', 0)))
            
            # Check current total payments
            current_total = deal.get_total_paid_amount()
            remaining_balance = float(deal.deal_value) - current_total
            
            if payment_amount > Decimal(str(remaining_balance + 0.01)):  # Allow small rounding differences
                raise ValidationError(
                    f'Payment amount ({payment_amount}) exceeds remaining balance ({remaining_balance:.2f})'
                )
            
            # Create the payment
            payment = Payment(
                deal=deal,
                payment_date=payment_data.get('payment_date', timezone.now().date()),
                received_amount=payment_amount,
                payment_type=payment_data.get('payment_type', 'bank'),
                payment_category=payment_data.get('payment_category', 'partial'),
                payment_remarks=payment_data.get('payment_remarks', ''),
                cheque_number=payment_data.get('cheque_number'),
                receipt_file=payment_data.get('receipt_file')
            )
            
            # Validate the payment
            payment.full_clean()
            payment.save()
            
            # Update deal payment count
            deal.payment_count = deal.payments.count()
            
            # Determine if deal should be marked as fully paid
            new_total = deal.get_total_paid_amount()
            deal_value = float(deal.deal_value)
            
            if abs(new_total - deal_value) <= 0.01:  # Fully paid (within 1 cent)
                if deal.payment_status != 'full_payment':
                    deal.payment_status = 'full_payment'
            elif new_total > 0 and deal.payment_status == 'initial payment':
                deal.payment_status = 'partial_payment'
            
            deal.save()
            
            # Create audit trail
            try:
                AuditTrail.objects.create(
                    table_name='deals_payment',
                    record_id=str(payment.id),
                    action='CREATE',
                    new_values={
                        'deal_id': str(deal.id),
                        'received_amount': float(payment.received_amount),
                        'payment_type': payment.payment_type,
                        'payment_date': payment.payment_date.isoformat()
                    },
                    user=user,
                    changes_summary={
                        'payment_created': float(payment.received_amount),
                        'new_total_paid': new_total,
                        'remaining_balance': deal_value - new_total
                    }
                )
            except Exception as e:
                logger.error(f"Failed to create audit trail for payment {payment.id}: {str(e)}")
            
            logger.info(f"Payment created for deal {deal_id}: {payment_amount} by {user.email if user else 'system'}")
            
            return {
                'payment_id': payment.id,
                'deal_id': str(deal.id),
                'amount': float(payment.received_amount),
                'new_total_paid': new_total,
                'remaining_balance': deal_value - new_total,
                'deal_payment_status': deal.payment_status,
                'created_at': payment.created_at.isoformat()
            }
    
    @classmethod
    def atomic_commission_calculation(cls, commission_id: int, recalculate_sales: bool = True, user=None) -> Dict:
        """
        Atomically recalculate commission with proper locking
        """
        from commission.models import Commission
        from apps.deals.models import Deal
        from core_config.models import AuditTrail
        
        with cls.atomic_commission_operation(commission_id, 'calculation') as commission:
            old_values = {
                'total_sales': float(commission.total_sales),
                'commission_amount': float(commission.commission_amount),
                'total_commission': float(commission.total_commission),
                'total_receivable': float(commission.total_receivable)
            }
            
            # Recalculate sales if requested
            if recalculate_sales:
                # Get verified deals for the commission period
                verified_deals = Deal.objects.filter(
                    created_by=commission.user,
                    organization=commission.organization,
                    verification_status='verified',
                    deal_date__gte=commission.start_date,
                    deal_date__lte=commission.end_date
                ).aggregate(
                    total_sales=models.Sum('deal_value')
                )
                
                commission.total_sales = verified_deals['total_sales'] or Decimal('0.00')
            
            # Recalculate commission amounts
            commission._calculate_amounts()
            commission.save()
            
            new_values = {
                'total_sales': float(commission.total_sales),
                'commission_amount': float(commission.commission_amount),
                'total_commission': float(commission.total_commission),
                'total_receivable': float(commission.total_receivable)
            }
            
            # Calculate changes
            changes = {}
            for key in old_values:
                if abs(old_values[key] - new_values[key]) > 0.01:
                    changes[key] = {
                        'old': old_values[key],
                        'new': new_values[key]
                    }
            
            # Create audit trail if there are changes
            if changes:
                try:
                    AuditTrail.objects.create(
                        table_name='commission_commission',
                        record_id=str(commission.id),
                        action='RECALCULATE',
                        old_values=old_values,
                        new_values=new_values,
                        user=user,
                        changes_summary=changes
                    )
                except Exception as e:
                    logger.error(f"Failed to create audit trail for commission {commission_id}: {str(e)}")
                
                logger.info(f"Commission {commission_id} recalculated by {user.email if user else 'system'}: {changes}")
            
            return {
                'commission_id': commission.id,
                'user_email': commission.user.email,
                'changes': changes,
                'current_values': new_values,
                'recalculated_at': timezone.now().isoformat()
            }
    
    @classmethod
    def atomic_bulk_deal_status_update(cls, deal_ids: List[str], status_updates: Dict, user=None) -> Dict:
        """
        Atomically update multiple deals with proper locking order to prevent deadlocks
        """
        from apps.deals.models import Deal
        
        # Sort deal IDs to ensure consistent locking order and prevent deadlocks
        sorted_deal_ids = sorted(deal_ids)
        
        results = []
        failed_updates = []
        
        with transaction.atomic():
            # Lock all deals in sorted order
            deals = Deal.objects.select_for_update().filter(
                id__in=sorted_deal_ids
            ).order_by('id')
            
            for deal in deals:
                try:
                    result = cls.atomic_deal_status_change(
                        str(deal.id),
                        status_updates.get('verification_status'),
                        status_updates.get('payment_status'),
                        user
                    )
                    results.append(result)
                    
                except Exception as e:
                    failed_updates.append({
                        'deal_id': str(deal.id),
                        'error': str(e)
                    })
                    logger.error(f"Failed to update deal {deal.id}: {str(e)}")
        
        return {
            'successful_updates': len(results),
            'failed_updates': len(failed_updates),
            'results': results,
            'failures': failed_updates,
            'updated_by': user.email if user else 'system',
            'updated_at': timezone.now().isoformat()
        }
    
    @classmethod
    def atomic_deal_verification_workflow(cls, deal_id: str, verification_decision: str, 
                                        verification_notes: str = '', user=None) -> Dict:
        """
        Complete atomic deal verification workflow with all related updates
        """
        from apps.deals.models import Deal
        from core_config.models import AuditTrail
        
        if verification_decision not in ['verified', 'rejected']:
            raise ValidationError("Verification decision must be 'verified' or 'rejected'")
        
        with cls.atomic_deal_operation(deal_id, 'verification_workflow') as deal:
            old_status = deal.verification_status
            
            # Validate transition
            deal.validate_verification_status_transition(verification_decision)
            
            # Update verification status
            deal.verification_status = verification_decision
            deal.updated_by = user
            
            # If verified and payments equal deal value, mark as fully paid
            if verification_decision == 'verified':
                total_paid = deal.get_total_paid_amount()
                deal_value = float(deal.deal_value)
                
                if abs(total_paid - deal_value) <= 0.01:
                    deal.payment_status = 'full_payment'
                elif total_paid > 0:
                    deal.payment_status = 'partial_payment'
            
            deal.save()
            
            # Create comprehensive audit trail
            try:
                AuditTrail.objects.create(
                    table_name='deals_deal',
                    record_id=str(deal.id),
                    action='VERIFICATION_WORKFLOW',
                    old_values={'verification_status': old_status},
                    new_values={
                        'verification_status': deal.verification_status,
                        'payment_status': deal.payment_status
                    },
                    user=user,
                    changes_summary={
                        'verification_decision': verification_decision,
                        'verification_notes': verification_notes,
                        'total_paid_amount': deal.get_total_paid_amount(),
                        'deal_value': float(deal.deal_value)
                    }
                )
            except Exception as e:
                logger.error(f"Failed to create verification audit trail for deal {deal_id}: {str(e)}")
            
            logger.info(f"Deal {deal_id} verification workflow completed: {old_status} -> {verification_decision} by {user.email if user else 'system'}")
            
            return {
                'deal_id': str(deal.id),
                'verification_decision': verification_decision,
                'old_status': old_status,
                'new_status': deal.verification_status,
                'payment_status': deal.payment_status,
                'verification_notes': verification_notes,
                'verified_by': user.email if user else 'system',
                'verified_at': timezone.now().isoformat()
            }


class OptimisticLockingMixin:
    """
    Mixin to add optimistic locking capabilities to Django models
    """
    
    def save_with_optimistic_lock(self, *args, **kwargs):
        """
        Save with optimistic locking using lock_version field
        """
        if not hasattr(self, 'lock_version'):
            # If no lock_version field, fall back to regular save
            return self.save(*args, **kwargs)
        
        if self.pk:
            # For updates, check version hasn't changed
            original_version = self.lock_version
            self.lock_version += 1
            
            # Update with version check
            updated_rows = self.__class__.objects.filter(
                pk=self.pk,
                lock_version=original_version
            ).update(
                lock_version=self.lock_version,
                **{field.name: getattr(self, field.name) 
                   for field in self._meta.fields 
                   if field.name not in ['id', 'lock_version', 'created_at']}
            )
            
            if updated_rows == 0:
                raise ValidationError(
                    "Record was modified by another user. Please refresh and try again."
                )
        else:
            # For new records, set initial version
            self.lock_version = 1
            return self.save(*args, **kwargs)
    
    def refresh_with_lock_check(self):
        """
        Refresh from database and check for concurrent modifications
        """
        if not self.pk:
            return
        
        current_version = self.lock_version if hasattr(self, 'lock_version') else None
        self.refresh_from_db()
        
        if current_version and hasattr(self, 'lock_version') and self.lock_version != current_version:
            logger.warning(f"Concurrent modification detected for {self.__class__.__name__} {self.pk}")
            return True  # Indicates concurrent modification
        
        return False