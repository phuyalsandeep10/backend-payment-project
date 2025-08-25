"""
Celery tasks for password management
"""

from celery import shared_task
from django.core.management import call_command
from django.utils import timezone
import logging

# Security logger
security_logger = logging.getLogger('security')

@shared_task
def check_password_expiration_task():
    """
    Celery task to check password expiration and send notifications
    """
    try:
        security_logger.info("Starting scheduled password expiration check")
        
        # Run the management command with warnings and expiration marking
        call_command(
            'check_password_expiration',
            '--send-warnings',
            '--mark-expired',
            verbosity=1
        )
        
        security_logger.info("Completed scheduled password expiration check")
        return "Password expiration check completed successfully"
        
    except Exception as e:
        security_logger.error(f"Password expiration check task failed: {str(e)}")
        raise

@shared_task
def send_password_policy_reminder(organization_id=None):
    """
    Send password policy reminders to users
    """
    try:
        from apps.authentication.models import User
        from authentication.password_policy import PasswordPolicy
        from django.core.mail import send_mail
        from django.conf import settings
        
        # Filter users by organization if specified
        users_query = User.objects.filter(is_active=True)
        if organization_id:
            users_query = users_query.filter(organization_id=organization_id)
        
        users = users_query.select_related('organization')
        policy = PasswordPolicy.get_policy_for_organization(organization_id)
        
        sent_count = 0
        
        for user in users:
            try:
                subject = "Password Policy Reminder - PRS System"
                message = f"""
Dear {user.first_name or user.username},

This is a reminder about the password policy for your organization in the PRS system:

Password Requirements:
- Minimum length: {policy['min_length']} characters
- Must contain uppercase letters: {'Yes' if policy['require_uppercase'] else 'No'}
- Must contain lowercase letters: {'Yes' if policy['require_lowercase'] else 'No'}
- Must contain numbers: {'Yes' if policy['require_numbers'] else 'No'}
- Must contain special characters: {'Yes' if policy['require_special_chars'] else 'No'}
- Password expires every: {policy['expiration_days']} days

Please ensure your password meets these requirements and change it regularly for security.

Best regards,
PRS System Security Team
                """
                
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=True,
                )
                
                sent_count += 1
                
            except Exception as e:
                security_logger.error(f"Failed to send policy reminder to {user.email}: {str(e)}")
        
        security_logger.info(f"Password policy reminders sent to {sent_count} users")
        return f"Password policy reminders sent to {sent_count} users"
        
    except Exception as e:
        security_logger.error(f"Password policy reminder task failed: {str(e)}")
        raise

@shared_task
def cleanup_password_history():
    """
    Clean up old password history records
    """
    try:
        from apps.authentication.models import PasswordHistory
        from datetime import timedelta
        
        # Remove password history older than 1 year
        cutoff_date = timezone.now() - timedelta(days=365)
        
        deleted_count = PasswordHistory.objects.filter(
            created_at__lt=cutoff_date
        ).delete()[0]
        
        security_logger.info(f"Cleaned up {deleted_count} old password history records")
        return f"Cleaned up {deleted_count} old password history records"
        
    except Exception as e:
        security_logger.error(f"Password history cleanup task failed: {str(e)}")
        raise