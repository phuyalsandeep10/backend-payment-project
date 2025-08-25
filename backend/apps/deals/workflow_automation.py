"""
Enhanced Deal Workflow Automation System
Provides background task processing and automated deal status transitions
"""

from django.db import transaction
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from celery import shared_task
from datetime import datetime, timedelta
from .models import Deal, Payment, PaymentApproval, ActivityLog
from apps.authentication.models import User
from decimal import Decimal
import logging

# Performance logger
performance_logger = logging.getLogger('performance')
security_logger = logging.getLogger('security')

class DealWorkflowEngine:
    """
    Core workflow engine for deal state management and automation
    """
    
    @classmethod
    def validate_status_transition(cls, deal, new_verification_status, new_payment_status=None, user=None):
        """
        Enhanced status transition validation with business logic
        """
        validation_result = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'required_actions': []
        }
        
        # Validate verification status transition
        if new_verification_status and new_verification_status != deal.verification_status:
            try:
                deal.validate_verification_status_transition(new_verification_status)
            except Exception as e:
                validation_result['is_valid'] = False
                validation_result['errors'].append(str(e))
        
        # Validate payment status transition
        if new_payment_status and new_payment_status != deal.payment_status:
            try:
                deal.validate_payment_status_transition(new_payment_status)
            except Exception as e:
                validation_result['is_valid'] = False
                validation_result['errors'].append(str(e))
        
        # Business logic validations
        if new_verification_status == 'verified':
            # Check if deal has sufficient payment documentation
            if not deal.payments.exists():
                validation_result['warnings'].append(
                    'Deal is being verified without any payment records'
                )
            
            # Check if all payments have approvals
            payments_without_approval = deal.payments.filter(approvals__isnull=True)
            if payments_without_approval.exists():
                validation_result['warnings'].append(
                    f'{payments_without_approval.count()} payments lack approval records'
                )
        
        if new_verification_status == 'rejected':
            # Ensure rejection reason is provided
            validation_result['required_actions'].append(
                'Rejection reason must be documented in deal remarks'
            )
        
        # Payment status business logic
        if new_payment_status == 'full_payment':
            total_paid = deal.get_total_paid_amount()
            deal_value = float(deal.deal_value)
            
            if abs(total_paid - deal_value) > 0.01:  # Allow for small rounding differences
                validation_result['warnings'].append(
                    f'Total paid amount ({total_paid}) does not match deal value ({deal_value})'
                )
        
        return validation_result
    
    @classmethod
    def execute_status_transition(cls, deal, new_verification_status=None, new_payment_status=None, 
                                user=None, remarks=None, notify_stakeholders=True):
        """
        Execute status transition with full workflow automation
        """
        with transaction.atomic():
            # Validate transition
            validation = cls.validate_status_transition(
                deal, new_verification_status, new_payment_status, user
            )
            
            if not validation['is_valid']:
                raise ValueError(f"Invalid transition: {', '.join(validation['errors'])}")
            
            # Store old values for logging
            old_verification_status = deal.verification_status
            old_payment_status = deal.payment_status
            
            # Update deal status
            if new_verification_status:
                deal.verification_status = new_verification_status
            
            if new_payment_status:
                deal.payment_status = new_payment_status
            
            if user:
                deal.updated_by = user
            
            if remarks:
                deal.deal_remarks = remarks
            
            deal.save()
            
            # Log the transition
            cls._log_status_transition(
                deal, old_verification_status, old_payment_status,
                new_verification_status, new_payment_status, user, remarks
            )
            
            # Execute post-transition actions
            cls._execute_post_transition_actions(
                deal, old_verification_status, old_payment_status,
                new_verification_status, new_payment_status, user, notify_stakeholders
            )
            
            return {
                'success': True,
                'warnings': validation['warnings'],
                'deal_id': deal.deal_id,
                'new_verification_status': deal.verification_status,
                'new_payment_status': deal.payment_status
            }
    
    @classmethod
    def _log_status_transition(cls, deal, old_verification, old_payment, 
                             new_verification, new_payment, user, remarks):
        """
        Log status transition in activity log
        """
        messages = []
        
        if new_verification and old_verification != new_verification:
            messages.append(f"Verification status changed from '{old_verification}' to '{new_verification}'")
        
        if new_payment and old_payment != new_payment:
            messages.append(f"Payment status changed from '{old_payment}' to '{new_payment}'")
        
        if remarks:
            messages.append(f"Remarks: {remarks}")
        
        if user:
            messages.append(f"Updated by: {user.email}")
        
        if messages:
            ActivityLog.objects.create(
                deal=deal,
                message="; ".join(messages)
            )
            
            security_logger.info(
                f"Deal {deal.deal_id} status transition: {'; '.join(messages)}"
            )
    
    @classmethod
    def _execute_post_transition_actions(cls, deal, old_verification, old_payment,
                                       new_verification, new_payment, user, notify_stakeholders):
        """
        Execute automated actions after status transition
        """
        # Queue background tasks for post-transition actions
        if new_verification == 'verified':
            # Queue verification completion tasks
            deal_verified_tasks.delay(deal.id, user.id if user else None)
        
        elif new_verification == 'rejected':
            # Queue rejection notification tasks
            deal_rejected_tasks.delay(deal.id, user.id if user else None)
        
        if new_payment == 'full_payment':
            # Queue full payment completion tasks
            deal_payment_completed_tasks.delay(deal.id, user.id if user else None)
        
        # Queue stakeholder notifications if requested
        if notify_stakeholders:
            notify_deal_stakeholders.delay(
                deal.id, 
                f"Status updated: {new_verification or deal.verification_status}",
                user.id if user else None
            )
    
    @classmethod
    def get_pending_workflow_actions(cls, organization=None, user=None):
        """
        Get deals that require workflow actions
        """
        from django.db.models import Q, Count
        from django.utils import timezone
        
        base_query = Deal.objects.select_related('client', 'created_by', 'organization')
        
        if organization:
            base_query = base_query.filter(organization=organization)
        
        # Deals pending verification for more than 24 hours
        verification_pending = base_query.filter(
            verification_status='pending',
            created_at__lt=timezone.now() - timedelta(hours=24)
        )
        
        # Deals with payments but no verification
        payment_without_verification = base_query.filter(
            payments__isnull=False,
            verification_status='pending'
        ).distinct()
        
        # Deals approaching due date without full payment
        approaching_due = base_query.filter(
            due_date__lte=timezone.now().date() + timedelta(days=7),
            due_date__gte=timezone.now().date(),
            payment_status__in=['initial payment', 'partial_payment']
        )
        
        # Deals with inconsistent payment status
        inconsistent_payment = []
        for deal in base_query.filter(payment_status='full_payment'):
            total_paid = deal.get_total_paid_amount()
            deal_value = float(deal.deal_value)
            if abs(total_paid - deal_value) > 0.01:
                inconsistent_payment.append(deal)
        
        return {
            'verification_pending': list(verification_pending),
            'payment_without_verification': list(payment_without_verification),
            'approaching_due': list(approaching_due),
            'inconsistent_payment': inconsistent_payment,
            'total_actions_required': (
                verification_pending.count() + 
                payment_without_verification.count() + 
                approaching_due.count() + 
                len(inconsistent_payment)
            )
        }
    
    @classmethod
    def auto_update_payment_status(cls, deal):
        """
        Automatically update payment status based on payment records
        """
        total_paid = deal.get_total_paid_amount()
        deal_value = float(deal.deal_value)
        
        if total_paid == 0:
            suggested_status = 'initial payment'
        elif abs(total_paid - deal_value) <= 0.01:  # Full payment (with small tolerance)
            suggested_status = 'full_payment'
        else:
            suggested_status = 'partial_payment'
        
        if suggested_status != deal.payment_status:
            return {
                'current_status': deal.payment_status,
                'suggested_status': suggested_status,
                'total_paid': total_paid,
                'deal_value': deal_value,
                'requires_update': True
            }
        
        return {'requires_update': False}


class DealPerformanceAnalyzer:
    """
    Analyzes deal performance and provides insights for workflow optimization
    """
    
    @classmethod
    def analyze_verification_performance(cls, organization=None, days=30):
        """
        Analyze verification workflow performance
        """
        from django.db.models import Avg, Count, Q
        from django.db.models.functions import Extract
        
        base_query = Deal.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=days)
        )
        
        if organization:
            base_query = base_query.filter(organization=organization)
        
        # Calculate verification metrics
        total_deals = base_query.count()
        verified_deals = base_query.filter(verification_status='verified').count()
        rejected_deals = base_query.filter(verification_status='rejected').count()
        pending_deals = base_query.filter(verification_status='pending').count()
        
        # Average time to verification
        verified_with_logs = base_query.filter(
            verification_status='verified',
            activity_logs__message__icontains='Verification status changed'
        ).distinct()
        
        verification_times = []
        for deal in verified_with_logs:
            verification_log = deal.activity_logs.filter(
                message__icontains='verified'
            ).first()
            if verification_log:
                time_diff = verification_log.timestamp - deal.created_at
                verification_times.append(time_diff.total_seconds() / 3600)  # Convert to hours
        
        avg_verification_time = sum(verification_times) / len(verification_times) if verification_times else 0
        
        # Verification rate by day of week
        verification_by_day = base_query.filter(
            verification_status='verified'
        ).annotate(
            day_of_week=Extract('created_at', 'week_day')
        ).values('day_of_week').annotate(
            count=Count('id')
        ).order_by('day_of_week')
        
        return {
            'total_deals': total_deals,
            'verified_deals': verified_deals,
            'rejected_deals': rejected_deals,
            'pending_deals': pending_deals,
            'verification_rate': (verified_deals / total_deals * 100) if total_deals > 0 else 0,
            'rejection_rate': (rejected_deals / total_deals * 100) if total_deals > 0 else 0,
            'avg_verification_time_hours': round(avg_verification_time, 2),
            'verification_by_day': list(verification_by_day),
            'analysis_period_days': days,
            'generated_at': timezone.now().isoformat()
        }
    
    @classmethod
    def analyze_payment_workflow_performance(cls, organization=None, days=30):
        """
        Analyze payment workflow performance
        """
        from django.db.models import Avg, Sum, Count
        
        base_query = Deal.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=days)
        )
        
        if organization:
            base_query = base_query.filter(organization=organization)
        
        # Payment completion metrics
        total_deals = base_query.count()
        full_payment_deals = base_query.filter(payment_status='full_payment').count()
        partial_payment_deals = base_query.filter(payment_status='partial_payment').count()
        initial_payment_deals = base_query.filter(payment_status='initial payment').count()
        
        # Average payment completion time
        payment_completion_times = []
        for deal in base_query.filter(payment_status='full_payment'):
            last_payment = deal.payments.order_by('-payment_date').first()
            if last_payment:
                time_diff = last_payment.payment_date - deal.deal_date
                payment_completion_times.append(time_diff.days)
        
        avg_payment_completion_days = (
            sum(payment_completion_times) / len(payment_completion_times) 
            if payment_completion_times else 0
        )
        
        # Payment method performance
        payment_method_performance = base_query.values('payment_method').annotate(
            count=Count('id'),
            avg_completion_rate=Avg(
                models.Case(
                    models.When(payment_status='full_payment', then=1),
                    default=0,
                    output_field=models.FloatField()
                )
            )
        ).order_by('-count')
        
        return {
            'total_deals': total_deals,
            'full_payment_deals': full_payment_deals,
            'partial_payment_deals': partial_payment_deals,
            'initial_payment_deals': initial_payment_deals,
            'payment_completion_rate': (full_payment_deals / total_deals * 100) if total_deals > 0 else 0,
            'avg_payment_completion_days': round(avg_payment_completion_days, 1),
            'payment_method_performance': list(payment_method_performance),
            'analysis_period_days': days,
            'generated_at': timezone.now().isoformat()
        }
    
    @classmethod
    def get_workflow_bottlenecks(cls, organization=None):
        """
        Identify workflow bottlenecks and optimization opportunities
        """
        bottlenecks = []
        
        # Check for deals stuck in pending verification
        pending_deals = Deal.objects.filter(
            verification_status='pending',
            created_at__lt=timezone.now() - timedelta(days=3)
        )
        
        if organization:
            pending_deals = pending_deals.filter(organization=organization)
        
        if pending_deals.count() > 0:
            bottlenecks.append({
                'type': 'verification_backlog',
                'severity': 'high' if pending_deals.count() > 10 else 'medium',
                'count': pending_deals.count(),
                'description': f'{pending_deals.count()} deals pending verification for more than 3 days',
                'recommendation': 'Assign additional verification resources or implement auto-verification rules'
            })
        
        # Check for payment inconsistencies
        inconsistent_payments = 0
        for deal in Deal.objects.filter(payment_status='full_payment'):
            if organization and deal.organization != organization:
                continue
            total_paid = deal.get_total_paid_amount()
            if abs(total_paid - float(deal.deal_value)) > 0.01:
                inconsistent_payments += 1
        
        if inconsistent_payments > 0:
            bottlenecks.append({
                'type': 'payment_inconsistency',
                'severity': 'medium',
                'count': inconsistent_payments,
                'description': f'{inconsistent_payments} deals have payment status inconsistencies',
                'recommendation': 'Run payment reconciliation process to fix inconsistencies'
            })
        
        # Check for overdue deals
        overdue_deals = Deal.objects.filter(
            due_date__lt=timezone.now().date(),
            payment_status__in=['initial payment', 'partial_payment']
        )
        
        if organization:
            overdue_deals = overdue_deals.filter(organization=organization)
        
        if overdue_deals.count() > 0:
            bottlenecks.append({
                'type': 'overdue_payments',
                'severity': 'high',
                'count': overdue_deals.count(),
                'description': f'{overdue_deals.count()} deals are overdue for payment',
                'recommendation': 'Implement automated payment reminders and follow-up processes'
            })
        
        return {
            'bottlenecks': bottlenecks,
            'total_issues': len(bottlenecks),
            'high_severity_count': len([b for b in bottlenecks if b['severity'] == 'high']),
            'analyzed_at': timezone.now().isoformat()
        }


# Celery tasks for background processing
@shared_task
def deal_verified_tasks(deal_id, user_id=None):
    """
    Background tasks to execute when a deal is verified
    """
    try:
        deal = Deal.objects.get(id=deal_id)
        user = User.objects.get(id=user_id) if user_id else None
        
        # Send verification notification to deal creator
        send_verification_notification.delay(deal_id, 'verified')
        
        # Update client status if this is their first verified deal
        if deal.client.deals.filter(verification_status='verified').count() == 1:
            deal.client.status = 'loyal'  # Assuming client has a status field
            # deal.client.save()
        
        # Log completion
        performance_logger.info(f"Deal {deal.deal_id} verification tasks completed")
        
        return f"Verification tasks completed for deal {deal.deal_id}"
        
    except Exception as e:
        performance_logger.error(f"Deal verification tasks failed for {deal_id}: {str(e)}")
        raise

@shared_task
def deal_rejected_tasks(deal_id, user_id=None):
    """
    Background tasks to execute when a deal is rejected
    """
    try:
        deal = Deal.objects.get(id=deal_id)
        user = User.objects.get(id=user_id) if user_id else None
        
        # Send rejection notification
        send_verification_notification.delay(deal_id, 'rejected')
        
        # Log rejection for analysis
        performance_logger.info(f"Deal {deal.deal_id} rejected - reason analysis needed")
        
        return f"Rejection tasks completed for deal {deal.deal_id}"
        
    except Exception as e:
        performance_logger.error(f"Deal rejection tasks failed for {deal_id}: {str(e)}")
        raise

@shared_task
def deal_payment_completed_tasks(deal_id, user_id=None):
    """
    Background tasks to execute when deal payment is completed
    """
    try:
        deal = Deal.objects.get(id=deal_id)
        user = User.objects.get(id=user_id) if user_id else None
        
        # Send payment completion notification
        send_payment_completion_notification.delay(deal_id)
        
        # Update commission calculations if applicable
        # calculate_commission.delay(deal_id)
        
        # Log completion
        performance_logger.info(f"Deal {deal.deal_id} payment completion tasks executed")
        
        return f"Payment completion tasks completed for deal {deal.deal_id}"
        
    except Exception as e:
        performance_logger.error(f"Deal payment completion tasks failed for {deal_id}: {str(e)}")
        raise

@shared_task
def notify_deal_stakeholders(deal_id, message, user_id=None):
    """
    Notify relevant stakeholders about deal status changes
    """
    try:
        deal = Deal.objects.select_related('client', 'created_by', 'organization').get(id=deal_id)
        
        # Notify deal creator
        if deal.created_by and deal.created_by.email:
            send_mail(
                subject=f'Deal Update: {deal.deal_id}',
                message=f'Your deal "{deal.deal_name}" has been updated.\n\n{message}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[deal.created_by.email],
                fail_silently=True
            )
        
        # Notify organization admins
        org_admins = User.objects.filter(
            organization=deal.organization,
            role__name='Organization Admin',
            is_active=True
        )
        
        for admin in org_admins:
            send_mail(
                subject=f'Deal Update: {deal.deal_id}',
                message=f'Deal "{deal.deal_name}" has been updated.\n\n{message}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[admin.email],
                fail_silently=True
            )
        
        performance_logger.info(f"Stakeholder notifications sent for deal {deal.deal_id}")
        
        return f"Stakeholder notifications sent for deal {deal.deal_id}"
        
    except Exception as e:
        performance_logger.error(f"Stakeholder notification failed for {deal_id}: {str(e)}")
        raise

@shared_task
def send_verification_notification(deal_id, status):
    """
    Send verification status notification
    """
    try:
        deal = Deal.objects.select_related('created_by').get(id=deal_id)
        
        if status == 'verified':
            subject = f'Deal Verified: {deal.deal_id}'
            message = f'Your deal "{deal.deal_name}" has been verified and approved.'
        else:
            subject = f'Deal Rejected: {deal.deal_id}'
            message = f'Your deal "{deal.deal_name}" has been rejected. Please review and resubmit if necessary.'
        
        if deal.created_by and deal.created_by.email:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[deal.created_by.email],
                fail_silently=True
            )
        
        return f"Verification notification sent for deal {deal.deal_id}"
        
    except Exception as e:
        performance_logger.error(f"Verification notification failed for {deal_id}: {str(e)}")
        raise

@shared_task
def send_payment_completion_notification(deal_id):
    """
    Send payment completion notification
    """
    try:
        deal = Deal.objects.select_related('created_by', 'client').get(id=deal_id)
        
        subject = f'Payment Completed: {deal.deal_id}'
        message = f'Payment for deal "{deal.deal_name}" with {deal.client.client_name} has been completed.'
        
        if deal.created_by and deal.created_by.email:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[deal.created_by.email],
                fail_silently=True
            )
        
        return f"Payment completion notification sent for deal {deal.deal_id}"
        
    except Exception as e:
        performance_logger.error(f"Payment completion notification failed for {deal_id}: {str(e)}")
        raise

@shared_task
def automated_workflow_maintenance():
    """
    Periodic task to maintain workflow health and identify issues
    """
    try:
        from apps.organization.models import Organization
        
        maintenance_results = []
        
        for org in Organization.objects.filter(is_active=True):
            # Get pending workflow actions
            pending_actions = DealWorkflowEngine.get_pending_workflow_actions(organization=org)
            
            if pending_actions['total_actions_required'] > 0:
                maintenance_results.append({
                    'organization': org.name,
                    'pending_actions': pending_actions['total_actions_required'],
                    'verification_pending': len(pending_actions['verification_pending']),
                    'approaching_due': len(pending_actions['approaching_due'])
                })
        
        # Log maintenance results
        performance_logger.info(f"Workflow maintenance completed: {len(maintenance_results)} organizations with pending actions")
        
        return {
            'organizations_processed': Organization.objects.filter(is_active=True).count(),
            'organizations_with_issues': len(maintenance_results),
            'maintenance_results': maintenance_results
        }
        
    except Exception as e:
        performance_logger.error(f"Automated workflow maintenance failed: {str(e)}")
        raise