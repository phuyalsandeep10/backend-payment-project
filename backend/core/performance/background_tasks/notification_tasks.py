"""
Notification Background Tasks

This module handles email notification tasks including:
- Password request notifications
- Deal-related notifications
- User account notifications

Extracted from background_task_processor.py for better organization.
"""

from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from typing import Dict, Any, List, Tuple, Optional

# Task logger
logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=3)
def send_password_request_notification(self, user_id, request_type, additional_data=None):
    """
    Background task for sending password request notifications
    """
    try:
        from apps.authentication.models import User
        
        user = User.objects.get(id=user_id)
        
        logger.info(f"Sending password request notification to {user.email}")
        
        result = {
            'user_id': user_id,
            'user_email': user.email,
            'request_type': request_type,
            'started_at': timezone.now().isoformat(),
            'success': False
        }
        
        # Prepare email content based on request type
        if request_type == 'password_reset':
            subject = 'Password Reset Request'
            message = f"""
            Hello {user.first_name or user.email},
            
            You have requested a password reset for your account.
            
            If you did not request this, please ignore this email.
            
            Best regards,
            The PRS Team
            """
            
        elif request_type == 'password_created':
            subject = 'Your Account Password Has Been Set'
            message = f"""
            Hello {user.first_name or user.email},
            
            Your account password has been successfully set by an administrator.
            
            You can now log in to your account.
            
            Best regards,
            The PRS Team
            """
            
        elif request_type == 'password_expiry_warning':
            days_until_expiry = additional_data.get('days_until_expiry', 7) if additional_data else 7
            subject = 'Password Expiry Warning'
            message = f"""
            Hello {user.first_name or user.email},
            
            Your password will expire in {days_until_expiry} days.
            
            Please change your password before it expires to avoid account lockout.
            
            Best regards,
            The PRS Team
            """
            
        else:
            raise ValueError(f"Unknown password request type: {request_type}")
        
        # Send email
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False
        )
        
        result['success'] = True
        result['completed_at'] = timezone.now().isoformat()
        
        logger.info(f"Password request notification sent to {user.email}")
        return result
        
    except Exception as e:
        logger.error(f"Password request notification failed: {str(e)}")
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying password notification in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise


@shared_task(bind=True, max_retries=3)
def send_deal_notification(self, deal_id, notification_type, user_id=None, additional_data=None):
    """
    Background task for sending deal-related notifications
    """
    try:
        from deals.models import Deal
        from apps.authentication.models import User
        
        deal = Deal.objects.select_related('client', 'organization', 'created_by').get(id=deal_id)
        user = User.objects.get(id=user_id) if user_id else None
        
        logger.info(f"Sending deal notification: {notification_type} for deal {deal.deal_id}")
        
        result = {
            'deal_id': deal.deal_id,
            'notification_type': notification_type,
            'started_at': timezone.now().isoformat(),
            'success': False,
            'recipients': []
        }
        
        # Determine recipients
        recipients = _get_notification_recipients(deal, notification_type)
        
        # Prepare email content
        subject, message = _prepare_deal_notification_content(deal, notification_type, additional_data)
        
        # Send emails
        for recipient in recipients:
            try:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[recipient],
                    fail_silently=False
                )
                result['recipients'].append({'email': recipient, 'status': 'sent'})
                
            except Exception as e:
                result['recipients'].append({'email': recipient, 'status': 'failed', 'error': str(e)})
        
        result['success'] = True
        result['completed_at'] = timezone.now().isoformat()
        
        logger.info(f"Deal notification sent for deal {deal.deal_id}")
        return result
        
    except Exception as e:
        logger.error(f"Deal notification failed: {str(e)}")
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying deal notification in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise


def _get_notification_recipients(deal, notification_type: str) -> List[str]:
    """Determine recipients for deal notifications"""
    from apps.authentication.models import User
    
    recipients = []
    
    if notification_type in ['verification_approved', 'verification_rejected']:
        # Notify deal creator
        if deal.created_by and deal.created_by.email:
            recipients.append(deal.created_by.email)
    
    elif notification_type == 'payment_received':
        # Notify deal creator and organization admins
        if deal.created_by and deal.created_by.email:
            recipients.append(deal.created_by.email)
        
        # Add organization admins
        org_admins = User.objects.filter(
            organization=deal.organization,
            role__name__icontains='admin',
            is_active=True
        )
        for admin in org_admins:
            if admin.email and admin.email not in recipients:
                recipients.append(admin.email)
    
    elif notification_type == 'deal_overdue':
        # Notify relevant stakeholders
        if deal.created_by and deal.created_by.email:
            recipients.append(deal.created_by.email)
    
    return recipients


def _prepare_deal_notification_content(deal, notification_type: str, additional_data: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """Prepare email content for deal notifications"""
    
    if notification_type == 'verification_approved':
        subject = f'Deal Verified: {deal.deal_id}'
        message = f"""
        Your deal "{deal.deal_name}" (ID: {deal.deal_id}) has been verified and approved.
        
        Deal Details:
        - Client: {deal.client.client_name if deal.client else 'N/A'}
        - Value: {deal.deal_value} {deal.currency}
        - Date: {deal.deal_date}
        
        You can now proceed with the next steps.
        """
        
    elif notification_type == 'verification_rejected':
        subject = f'Deal Rejected: {deal.deal_id}'
        message = f"""
        Your deal "{deal.deal_name}" (ID: {deal.deal_id}) has been rejected.
        
        Please review the deal details and resubmit if necessary.
        """
        
    elif notification_type == 'payment_received':
        payment_amount = additional_data.get('payment_amount', 0) if additional_data else 0
        subject = f'Payment Received: {deal.deal_id}'
        message = f"""
        A payment of {payment_amount} {deal.currency} has been received for deal "{deal.deal_name}" (ID: {deal.deal_id}).
        
        Deal Details:
        - Client: {deal.client.client_name if deal.client else 'N/A'}
        - Total Value: {deal.deal_value} {deal.currency}
        - Payment Received: {payment_amount} {deal.currency}
        """
        
    elif notification_type == 'deal_overdue':
        subject = f'Deal Overdue: {deal.deal_id}'
        message = f"""
        Deal "{deal.deal_name}" (ID: {deal.deal_id}) is overdue and requires attention.
        
        Deal Details:
        - Client: {deal.client.client_name if deal.client else 'N/A'}
        - Value: {deal.deal_value} {deal.currency}
        - Due Date: {deal.deal_date}
        
        Please take necessary action to resolve this issue.
        """
        
    else:
        subject = f'Deal Update: {deal.deal_id}'
        message = f"""
        There has been an update to deal "{deal.deal_name}" (ID: {deal.deal_id}).
        
        Notification Type: {notification_type}
        
        Please check your dashboard for more details.
        """
    
    return subject, message.strip()
