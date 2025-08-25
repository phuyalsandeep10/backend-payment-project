"""
Background Task Processor
Implements comprehensive background task processing for deal workflows, file processing, and email notifications
"""

from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.db import transaction
from datetime import timedelta
from typing import Dict, List, Optional, Any
import logging
import os
import tempfile
from PIL import Image
import io

# Task logger
logger = get_task_logger(__name__)

class BackgroundTaskProcessor:
    """
    Central processor for background tasks with monitoring and retry logic
    """
    
    # Task priorities
    PRIORITY_HIGH = 'high'
    PRIORITY_MEDIUM = 'medium'
    PRIORITY_LOW = 'low'
    
    # Retry settings
    MAX_RETRIES = 3
    RETRY_BACKOFF = True
    RETRY_JITTER = True
    
    @classmethod
    def get_task_status(cls, task_id: str) -> Dict[str, Any]:
        """Get status of a background task"""
        try:
            from celery.result import AsyncResult
            
            result = AsyncResult(task_id)
            
            return {
                'task_id': task_id,
                'status': result.status,
                'result': result.result if result.ready() else None,
                'traceback': result.traceback if result.failed() else None,
                'date_done': result.date_done.isoformat() if result.date_done else None,
                'successful': result.successful() if result.ready() else None,
                'failed': result.failed() if result.ready() else None
            }
            
        except Exception as e:
            logger.error(f"Failed to get task status for {task_id}: {str(e)}")
            return {'task_id': task_id, 'status': 'unknown', 'error': str(e)}
    
    @classmethod
    def queue_task_with_monitoring(cls, task_func, *args, priority=PRIORITY_MEDIUM, **kwargs):
        """Queue a task with monitoring and retry logic"""
        try:
            # Set task options based on priority
            task_options = {
                'retry': True,
                'retry_policy': {
                    'max_retries': cls.MAX_RETRIES,
                    'interval_start': 0,
                    'interval_step': 0.2,
                    'interval_max': 0.2,
                }
            }
            
            if priority == cls.PRIORITY_HIGH:
                task_options['queue'] = 'high_priority'
            elif priority == cls.PRIORITY_LOW:
                task_options['queue'] = 'low_priority'
            else:
                task_options['queue'] = 'default'
            
            # Queue the task
            result = task_func.apply_async(args=args, kwargs=kwargs, **task_options)
            
            logger.info(f"Queued task {task_func.name} with ID {result.id} (priority: {priority})")
            
            return {
                'task_id': result.id,
                'task_name': task_func.name,
                'priority': priority,
                'queued_at': timezone.now().isoformat(),
                'status': 'queued'
            }
            
        except Exception as e:
            logger.error(f"Failed to queue task {task_func.name}: {str(e)}")
            raise


# Deal Processing Tasks
@shared_task(bind=True, max_retries=3)
def process_deal_workflow(self, deal_id, workflow_action, user_id=None):
    """
    Background task for deal processing workflows
    """
    try:
        from deals.models import Deal, ActivityLog
        from apps.authentication.models import User
        
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

def _perform_deal_verification_checks(deal):
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
    
    return {
        'passed': passed_checks >= (total_checks * 0.8),  # 80% of checks must pass
        'score': passed_checks / total_checks,
        'checks': checks,
        'reasons': [check for check, passed in checks.items() if not passed]
    }

def _calculate_deal_commission(deal):
    """Calculate commission for deal"""
    try:
        # This would integrate with your commission calculation logic
        commission_rate = 0.05  # 5% default rate
        commission_amount = float(deal.deal_value) * commission_rate
        
        return {
            'commission_calculated': True,
            'commission_amount': commission_amount,
            'commission_rate': commission_rate,
            'deal_value': float(deal.deal_value)
        }
        
    except Exception as e:
        return {
            'commission_calculated': False,
            'error': str(e)
        }

def _update_deal_payment_status(deal):
    """Update deal payment status based on payments"""
    try:
        total_paid = deal.get_total_paid_amount()
        deal_value = float(deal.deal_value)
        
        if total_paid == 0:
            new_status = 'initial payment'
        elif abs(total_paid - deal_value) <= 0.01:
            new_status = 'full_payment'
        else:
            new_status = 'partial_payment'
        
        if new_status != deal.payment_status:
            deal.payment_status = new_status
            deal.save(update_fields=['payment_status', 'updated_at'])
            
            return {
                'payment_status_updated': True,
                'old_status': deal.payment_status,
                'new_status': new_status,
                'total_paid': total_paid,
                'deal_value': deal_value
            }
        
        return {
            'payment_status_updated': False,
            'current_status': deal.payment_status,
            'total_paid': total_paid
        }
        
    except Exception as e:
        return {
            'payment_status_updated': False,
            'error': str(e)
        }

def _generate_deal_invoice(deal):
    """Generate invoice for deal"""
    try:
        # This would integrate with your invoice generation logic
        invoice_number = f"INV-{deal.deal_id}-{timezone.now().strftime('%Y%m%d')}"
        
        return {
            'invoice_generated': True,
            'invoice_number': invoice_number,
            'deal_id': deal.deal_id,
            'amount': float(deal.deal_value)
        }
        
    except Exception as e:
        return {
            'invoice_generated': False,
            'error': str(e)
        }


# File Processing Tasks
@shared_task(bind=True, max_retries=3)
def process_profile_picture(self, user_id, file_path, original_filename):
    """
    Background task for processing profile pictures
    """
    try:
        from apps.authentication.models import User
        
        user = User.objects.get(id=user_id)
        
        logger.info(f"Processing profile picture for user {user.email}")
        
        result = {
            'user_id': user_id,
            'original_filename': original_filename,
            'started_at': timezone.now().isoformat(),
            'success': False,
            'processed_files': {}
        }
        
        # Process the image
        with Image.open(file_path) as img:
            # Verify image integrity
            img.verify()
            
            # Reopen for processing
            img = Image.open(file_path)
            
            # Convert to RGB if necessary
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            
            # Generate different sizes
            sizes = {
                'thumbnail': (150, 150),
                'medium': (300, 300),
                'large': (600, 600)
            }
            
            processed_files = {}
            
            for size_name, dimensions in sizes.items():
                # Resize image
                resized_img = img.copy()
                resized_img.thumbnail(dimensions, Image.Resampling.LANCZOS)
                
                # Save processed image
                output_buffer = io.BytesIO()
                resized_img.save(output_buffer, format='JPEG', quality=85, optimize=True)
                
                # Generate filename
                base_name = os.path.splitext(original_filename)[0]
                processed_filename = f"{base_name}_{size_name}.jpg"
                
                # Save to storage (this would integrate with your file storage system)
                processed_files[size_name] = {
                    'filename': processed_filename,
                    'size': output_buffer.tell(),
                    'dimensions': dimensions
                }
                
                logger.info(f"Generated {size_name} version: {processed_filename}")
        
        result['processed_files'] = processed_files
        result['success'] = True
        result['completed_at'] = timezone.now().isoformat()
        
        # Clean up original file
        if os.path.exists(file_path):
            os.remove(file_path)
        
        logger.info(f"Profile picture processing completed for user {user.email}")
        return result
        
    except Exception as e:
        logger.error(f"Profile picture processing failed: {str(e)}")
        
        # Clean up on failure
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying profile picture processing in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise

@shared_task(bind=True, max_retries=3)
def process_deal_attachment(self, deal_id, file_path, original_filename, file_type):
    """
    Background task for processing deal attachments
    """
    try:
        from deals.models import Deal
        
        deal = Deal.objects.get(id=deal_id)
        
        logger.info(f"Processing deal attachment for deal {deal.deal_id}")
        
        result = {
            'deal_id': deal.deal_id,
            'original_filename': original_filename,
            'file_type': file_type,
            'started_at': timezone.now().isoformat(),
            'success': False,
            'processing_details': {}
        }
        
        # Validate file security
        from core_config.file_security import validate_file_security_enhanced
        
        with open(file_path, 'rb') as f:
            validation_result = validate_file_security_enhanced(f)
            
            if not validation_result['is_safe']:
                raise ValueError(f"File security validation failed: {validation_result['reason']}")
        
        # Process based on file type
        if file_type.startswith('image/'):
            # Process image attachment
            processing_result = _process_image_attachment(file_path, original_filename)
        elif file_type == 'application/pdf':
            # Process PDF attachment
            processing_result = _process_pdf_attachment(file_path, original_filename)
        else:
            # Process generic file
            processing_result = _process_generic_attachment(file_path, original_filename)
        
        result['processing_details'] = processing_result
        result['success'] = True
        result['completed_at'] = timezone.now().isoformat()
        
        # Clean up original file
        if os.path.exists(file_path):
            os.remove(file_path)
        
        logger.info(f"Deal attachment processing completed for deal {deal.deal_id}")
        return result
        
    except Exception as e:
        logger.error(f"Deal attachment processing failed: {str(e)}")
        
        # Clean up on failure
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying deal attachment processing in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise

def _process_image_attachment(file_path, original_filename):
    """Process image attachment"""
    try:
        with Image.open(file_path) as img:
            # Get image info
            width, height = img.size
            format_name = img.format
            mode = img.mode
            
            # Generate thumbnail if image is large
            thumbnail_created = False
            if width > 800 or height > 800:
                thumbnail = img.copy()
                thumbnail.thumbnail((800, 800), Image.Resampling.LANCZOS)
                
                # Save thumbnail
                base_name = os.path.splitext(original_filename)[0]
                thumbnail_filename = f"{base_name}_thumb.jpg"
                
                thumbnail_buffer = io.BytesIO()
                thumbnail.save(thumbnail_buffer, format='JPEG', quality=85)
                
                thumbnail_created = True
            
            return {
                'file_type': 'image',
                'original_dimensions': (width, height),
                'format': format_name,
                'mode': mode,
                'thumbnail_created': thumbnail_created,
                'file_size': os.path.getsize(file_path)
            }
            
    except Exception as e:
        return {
            'file_type': 'image',
            'processing_error': str(e)
        }

def _process_pdf_attachment(file_path, original_filename):
    """Process PDF attachment"""
    try:
        file_size = os.path.getsize(file_path)
        
        # Basic PDF processing (you could add more sophisticated processing here)
        return {
            'file_type': 'pdf',
            'file_size': file_size,
            'processed': True
        }
        
    except Exception as e:
        return {
            'file_type': 'pdf',
            'processing_error': str(e)
        }

def _process_generic_attachment(file_path, original_filename):
    """Process generic file attachment"""
    try:
        file_size = os.path.getsize(file_path)
        file_extension = os.path.splitext(original_filename)[1].lower()
        
        return {
            'file_type': 'generic',
            'file_size': file_size,
            'file_extension': file_extension,
            'processed': True
        }
        
    except Exception as e:
        return {
            'file_type': 'generic',
            'processing_error': str(e)
        }


# Email Notification Tasks
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

def _prepare_deal_notification_content(deal, notification_type, additional_data):
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
        - Payment Status: {deal.payment_status}
        """
        
    elif notification_type == 'deal_overdue':
        subject = f'Deal Overdue: {deal.deal_id}'
        message = f"""
        Deal "{deal.deal_name}" (ID: {deal.deal_id}) is overdue for payment.
        
        Due Date: {deal.due_date}
        Outstanding Amount: {deal.get_remaining_balance()} {deal.currency}
        
        Please follow up with the client.
        """
        
    else:
        subject = f'Deal Update: {deal.deal_id}'
        message = f'Deal "{deal.deal_name}" has been updated.'
    
    return subject, message


# Task Monitoring and Management
@shared_task
def monitor_background_tasks():
    """
    Monitor background tasks and report on their status
    """
    try:
        from celery import current_app
        
        logger.info("Starting background task monitoring")
        
        # Get active tasks
        inspect = current_app.control.inspect()
        
        active_tasks = inspect.active()
        scheduled_tasks = inspect.scheduled()
        reserved_tasks = inspect.reserved()
        
        monitoring_report = {
            'timestamp': timezone.now().isoformat(),
            'active_tasks': active_tasks or {},
            'scheduled_tasks': scheduled_tasks or {},
            'reserved_tasks': reserved_tasks or {},
            'summary': {
                'total_active': sum(len(tasks) for tasks in (active_tasks or {}).values()),
                'total_scheduled': sum(len(tasks) for tasks in (scheduled_tasks or {}).values()),
                'total_reserved': sum(len(tasks) for tasks in (reserved_tasks or {}).values())
            }
        }
        
        logger.info(f"Background task monitoring completed: {monitoring_report['summary']}")
        
        return monitoring_report
        
    except Exception as e:
        logger.error(f"Background task monitoring failed: {str(e)}")
        raise

@shared_task
def cleanup_failed_tasks():
    """
    Clean up failed tasks and retry if appropriate
    """
    try:
        logger.info("Starting failed task cleanup")
        
        # This would implement cleanup logic for failed tasks
        # For now, we'll just log the action
        
        cleanup_results = {
            'timestamp': timezone.now().isoformat(),
            'failed_tasks_cleaned': 0,
            'tasks_retried': 0
        }
        
        logger.info("Failed task cleanup completed")
        
        return cleanup_results
        
    except Exception as e:
        logger.error(f"Failed task cleanup failed: {str(e)}")
        raise