"""
Deal Processing Background Tasks

This module handles deal workflow processing tasks including:
- Deal verification
- Commission calculation
- Payment status updates
- Invoice generation

Extracted from background_task_processor.py for better organization.
"""

from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from django.db import transaction
from typing import Dict, Any

# Task logger
logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=3)
def process_deal_workflow(self, deal_id, workflow_action, user_id=None):
    """
    Background task for deal processing workflows
    """
    try:
        from deals.models import Deal, ActivityLog
        from apps.authentication.models import User
        from .notification_tasks import send_deal_notification
        
        deal = Deal.objects.select_related('client', 'organization', 'created_by').get(id=deal_id)
        user = User.objects.get(id=user_id) if user_id else None
        
        logger.info(f"Processing deal workflow: {workflow_action} for deal {deal.deal_id}")
        
        result = {
            'deal_id': deal.deal_id,
            'workflow_action': workflow_action,
            'started_at': timezone.now().isoformat(),
            'success': False,
            'details': {}
        }
        
        with transaction.atomic():
            if workflow_action == 'verify_deal':
                # Process deal verification
                if deal.verification_status == 'pending':
                    # Perform verification checks
                    verification_result = _perform_deal_verification_checks(deal)
                    
                    if verification_result['passed']:
                        deal.verification_status = 'verified'
                        deal.save(update_fields=['verification_status', 'updated_at'])
                        
                        # Log activity
                        ActivityLog.objects.create(
                            deal=deal,
                            message=f"Deal automatically verified via background processing"
                        )
                        
                        # Queue notification task
                        send_deal_notification.delay(
                            deal_id=deal_id,
                            notification_type='verification_approved',
                            user_id=user_id
                        )
                        
                        result['details'] = {'verification_status': 'verified'}
                    else:
                        result['details'] = {
                            'verification_status': 'failed',
                            'reasons': verification_result['reasons']
                        }
                
            elif workflow_action == 'calculate_commission':
                # Process commission calculation
                commission_result = _calculate_deal_commission(deal)
                result['details'] = commission_result
                
            elif workflow_action == 'update_payment_status':
                # Update payment status based on payments
                payment_result = _update_deal_payment_status(deal)
                result['details'] = payment_result
                
            elif workflow_action == 'generate_invoice':
                # Generate invoice for deal
                invoice_result = _generate_deal_invoice(deal)
                result['details'] = invoice_result
            
            else:
                raise ValueError(f"Unknown workflow action: {workflow_action}")
        
        result['success'] = True
        result['completed_at'] = timezone.now().isoformat()
        
        logger.info(f"Deal workflow processing completed for {deal.deal_id}")
        return result
        
    except Exception as e:
        logger.error(f"Deal workflow processing failed: {str(e)}")
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying deal workflow processing in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise


def _perform_deal_verification_checks(deal) -> Dict[str, Any]:
    """Perform automated deal verification checks"""
    checks = {
        'has_client': bool(deal.client),
        'has_deal_value': deal.deal_value > 0,
        'has_payment_method': bool(deal.payment_method),
        'has_deal_date': bool(deal.deal_date),
        'has_payments': deal.payments.exists()
    }
    
    passed_checks = sum(checks.values())
    total_checks = len(checks)
    
    # Require at least 80% of checks to pass
    passing_threshold = 0.8
    passed = passed_checks / total_checks >= passing_threshold
    
    reasons = [f"Missing {check.replace('has_', '')}" for check, result in checks.items() if not result]
    
    return {
        'passed': passed,
        'score': passed_checks / total_checks,
        'checks': checks,
        'reasons': reasons
    }


def _calculate_deal_commission(deal) -> Dict[str, Any]:
    """Calculate commission for a deal"""
    try:
        from commission.models import Commission, CommissionRule
        from decimal import Decimal
        
        # Get organization commission rules
        commission_rules = CommissionRule.objects.filter(
            organization=deal.organization,
            is_active=True
        ).order_by('-created_at')
        
        if not commission_rules.exists():
            return {
                'success': False,
                'error': 'No active commission rules found for organization'
            }
        
        rule = commission_rules.first()
        
        # Calculate commission based on rule
        if rule.calculation_method == 'percentage':
            commission_amount = deal.deal_value * (rule.commission_percentage / Decimal('100'))
        elif rule.calculation_method == 'fixed':
            commission_amount = rule.fixed_amount
        else:
            commission_amount = Decimal('0')
        
        # Create or update commission record
        commission, created = Commission.objects.update_or_create(
            deal=deal,
            defaults={
                'commission_amount': commission_amount,
                'commission_rule': rule,
                'calculation_date': timezone.now()
            }
        )
        
        return {
            'success': True,
            'commission_amount': float(commission_amount),
            'rule_applied': rule.name,
            'created_new': created
        }
        
    except Exception as e:
        logger.error(f"Commission calculation failed for deal {deal.deal_id}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }


def _update_deal_payment_status(deal) -> Dict[str, Any]:
    """Update deal payment status based on payments"""
    try:
        from decimal import Decimal
        
        # Calculate total payments
        from django.db import models
        total_payments = deal.payments.aggregate(
            total=models.Sum('amount')
        )['total'] or Decimal('0')
        
        # Determine payment status
        if total_payments >= deal.deal_value:
            payment_status = 'fully_paid'
            is_fully_paid = True
        elif total_payments > Decimal('0'):
            payment_status = 'partially_paid'
            is_fully_paid = False
        else:
            payment_status = 'pending'
            is_fully_paid = False
        
        # Update deal
        deal.payment_status = payment_status
        deal.is_fully_paid = is_fully_paid
        deal.total_payments = total_payments
        deal.save(update_fields=['payment_status', 'is_fully_paid', 'total_payments', 'updated_at'])
        
        return {
            'success': True,
            'payment_status': payment_status,
            'total_payments': float(total_payments),
            'deal_value': float(deal.deal_value),
            'is_fully_paid': is_fully_paid
        }
        
    except Exception as e:
        logger.error(f"Payment status update failed for deal {deal.deal_id}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }


def _generate_deal_invoice(deal) -> Dict[str, Any]:
    """Generate invoice for deal"""
    try:
        # Mock invoice generation - implement actual logic as needed
        invoice_number = f"INV-{deal.deal_id}-{timezone.now().strftime('%Y%m%d')}"
        
        # Update deal with invoice information
        deal.invoice_number = invoice_number
        deal.invoice_generated_at = timezone.now()
        deal.save(update_fields=['invoice_number', 'invoice_generated_at', 'updated_at'])
        
        return {
            'success': True,
            'invoice_number': invoice_number,
            'generated_at': deal.invoice_generated_at.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Invoice generation failed for deal {deal.deal_id}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }
