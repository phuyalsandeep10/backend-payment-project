
from django.conf import settings
from django.template import Template, Context
from django.utils import timezone
from django.db.models import Q
from authentication.models import User
from permissions.models import Role
from .models import Notification, NotificationSettings, EmailNotificationLog, NotificationTemplate
import logging
import json

logger = logging.getLogger(__name__)

class NotificationService:
    """
    Service for creating and managing notifications.
    """
    
    @staticmethod
    def create_notification(
        notification_type,
        title,
        message,
        recipient=None,
        recipients=None,
        organization=None,
        priority='medium',
        category='business',
        related_object_type=None,
        related_object_id=None,
        action_url=None,
        context_data=None,
        send_email_to_superadmin=False
    ):
        """
        Create notifications for one or multiple recipients.
        
        Args:
            notification_type: Type of notification (from TYPE_CHOICES)
            title: Notification title (can be template)
            message: Notification message (can be template)
            recipient: Single recipient User object
            recipients: List of recipient User objects
            organization: Organization context
            priority: Priority level
            category: Notification category
            related_object_type: Type of related object (e.g., 'client', 'deal')
            related_object_id: ID of related object
            action_url: Frontend URL for action
            context_data: Dict of template variables
            send_email_to_superadmin: Whether to send email to super-admin
        
        Returns:
            List of created Notification objects
        """
        created_notifications = []
        
        # Determine recipients
        if recipient:
            recipients = [recipient]
        elif not recipients:
            recipients = []
        
        # Get or create notification template
        template = NotificationService._get_notification_template(notification_type)
        
        # Process template variables
        if context_data and template:
            title = NotificationService._render_template(template.title_template, context_data)
            message = NotificationService._render_template(template.message_template, context_data)
        
        # Create notifications for each recipient
        for recipient_user in recipients:
            # Check user notification preferences
            if not NotificationService._should_notify_user(recipient_user, notification_type, priority):
                continue
                
            notification = Notification.objects.create(
                title=title,
                message=message,
                notification_type=notification_type,
                priority=priority,
                category=category,
                recipient=recipient_user,
                organization=organization,
                related_object_type=related_object_type,
                related_object_id=related_object_id,
                action_url=action_url
            )
            created_notifications.append(notification)
        
        # Send email to super-admin if requested
        if send_email_to_superadmin and created_notifications:
            NotificationService._queue_superadmin_email(
                notification_type=notification_type,
                title=title,
                message=message,
                organization=organization,
                priority=priority,
                notification_count=len(created_notifications)
            )
        
        return created_notifications
    
    @staticmethod
    def notify_role_based_users(
        organization,
        notification_type,
        title,
        message,
        target_roles=None,
        priority='medium',
        category='business',
        context_data=None,
        send_email_to_superadmin=False,
        **kwargs
    ):
        """
        Create notifications for users based on their roles within an organization.
        
        Args:
            organization: Organization object
            target_roles: List of role names to notify (e.g., ['admin', 'team_lead'])
            ... other args same as create_notification
        """
        recipients = []
        
        if target_roles:
            # Get users with specific roles
            users = User.objects.filter(
                organization=organization,
                role__name__in=target_roles,
                is_active=True
            )
            recipients.extend(users)
        else:
            # Notify all active users in organization
            users = User.objects.filter(
                organization=organization,
                is_active=True
            )
            recipients.extend(users)
        
        return NotificationService.create_notification(
            notification_type=notification_type,
            title=title,
            message=message,
            recipients=recipients,
            organization=organization,
            priority=priority,
            category=category,
            context_data=context_data,
            send_email_to_superadmin=send_email_to_superadmin,
            **kwargs
        )
    
    @staticmethod
    def notify_organization_admins(
        organization,
        notification_type,
        title,
        message,
        priority='medium',
        context_data=None,
        send_email_to_superadmin=False,
        **kwargs
    ):
        """
        Notify all organization administrators.
        """
        # Get org admin role
        admin_roles = Role.objects.filter(
            organization=organization,
            name__icontains='admin'
        )
        
        if admin_roles.exists():
            admin_users = User.objects.filter(
                organization=organization,
                role__in=admin_roles,
                is_active=True
            )
        else:
            # Fallback to users with is_staff=True in the organization
            admin_users = User.objects.filter(
                organization=organization,
                is_staff=True,
                is_active=True
            )
        
        return NotificationService.create_notification(
            notification_type=notification_type,
            title=title,
            message=message,
            recipients=list(admin_users),
            organization=organization,
            priority=priority,
            category='user_management',
            context_data=context_data,
            send_email_to_superadmin=send_email_to_superadmin,
            **kwargs
        )
    
    @staticmethod
    def _should_notify_user(user, notification_type, priority):
        """
        Check if user should receive this notification based on their preferences.
        """
        try:
            settings = user.notification_settings
        except NotificationSettings.DoesNotExist:
            # Create default settings
            settings = NotificationSettings.objects.create(user=user)
        
        # Check type-specific preferences
        type_enabled = True
        if 'client' in notification_type:
            type_enabled = settings.enable_client_notifications
        elif 'deal' in notification_type:
            type_enabled = settings.enable_deal_notifications
        elif 'user' in notification_type or 'role' in notification_type:
            type_enabled = settings.enable_user_management_notifications
        elif 'team' in notification_type:
            type_enabled = settings.enable_team_notifications
        elif 'project' in notification_type:
            type_enabled = settings.enable_project_notifications
        elif 'commission' in notification_type:
            type_enabled = settings.enable_commission_notifications
        elif 'system' in notification_type:
            type_enabled = settings.enable_system_notifications
        
        if not type_enabled:
            return False
        
        # Check priority filter
        priority_order = {'low': 1, 'medium': 2, 'high': 3, 'urgent': 4}
        min_priority = priority_order.get(settings.min_priority, 1)
        current_priority = priority_order.get(priority, 2)
        
        return current_priority >= min_priority
    
    @staticmethod
    def _get_notification_template(notification_type):
        """
        Get or create notification template for the given type.
        """
        try:
            return NotificationTemplate.objects.get(
                notification_type=notification_type,
                is_active=True
            )
        except NotificationTemplate.DoesNotExist:
            return None
    
    @staticmethod
    def _render_template(template_string, context_data):
        """
        Render Django template string with context data.
        """
        if not template_string or not context_data:
            return template_string
        
        try:
            template = Template(template_string)
            context = Context(context_data)
            return template.render(context)
        except Exception as e:
            logger.error(f"Template rendering error: {e}")
            return template_string
    
    @staticmethod
    def _queue_superadmin_email(
        notification_type,
        title,
        message,
        organization=None,
        priority='medium',
        notification_count=1
    ):
        """
        Queue email notification to super-admin.
        """
        # Get super-admin email
        superadmin_email = getattr(settings, 'SUPER_ADMIN_OTP_EMAIL', None)
        if not superadmin_email:
            logger.warning("SUPER_ADMIN_OTP_EMAIL not configured")
            return
        
        # Create email subject and content
        subject = f"PRS Alert: {title}"
        if organization:
            subject += f" - {organization.name}"
        
        content = f"""
        Notification Alert from Payment Receiving System (PRS)
        
        Type: {notification_type.replace('_', ' ').title()}
        Priority: {priority.upper()}
        Organization: {organization.name if organization else 'System-wide'}
        
        Details:
        {message}
        
        Users Notified: {notification_count}
        
        Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        
        ---
        This is an automated notification from PRS System.
        """
        
        # Create email log entry
        email_log = EmailNotificationLog.objects.create(
            email_type='instant_alert',
            recipient_email=superadmin_email,
            subject=subject,
            content=content,
            notification_count=notification_count,
            priority=priority
        )
        
        # Send email asynchronously (or immediately for now)
        NotificationService._send_email_notification(email_log)
    
    @staticmethod
    def _send_email_notification(email_log):
        """
        Send email notification using robust email backend.
        """
        try:
            from core_config.email_backend import EmailService
            
            success = EmailService.send_email(
                subject=email_log.subject,
                message=email_log.content,
                recipient_list=[email_log.recipient_email],
                fail_silently=True  # Don't break system on email failures
            )
            
            if success:
                email_log.mark_sent()
                logger.info(f"Email sent successfully to {email_log.recipient_email}")
            else:
                email_log.mark_failed("Email sending failed via robust backend")
                logger.warning(f"Email sending failed to {email_log.recipient_email}")
            
        except Exception as e:
            error_message = str(e)
            email_log.mark_failed(error_message)
            logger.error(f"Failed to send email to {email_log.recipient_email}: {error_message}")
    
    @staticmethod
    def mark_notifications_as_read(user, notification_ids=None):
        """
        Mark notifications as read for a user.
        
        Args:
            user: User object
            notification_ids: List of notification IDs (if None, marks all unread)
        """
        notifications = Notification.objects.filter(
            recipient=user,
            is_read=False
        )
        
        if notification_ids:
            notifications = notifications.filter(id__in=notification_ids)
        
        count = notifications.count()
        notifications.update(
            is_read=True,
            read_at=timezone.now()
        )
        
        return count
    
    @staticmethod
    def get_user_notifications(user, limit=50, unread_only=False):
        """
        Get notifications for a user.
        
        Args:
            user: User object
            limit: Maximum number of notifications to return
            unread_only: If True, only return unread notifications
        
        Returns:
            QuerySet of Notification objects
        """
        notifications = Notification.objects.filter(recipient=user)
        
        if unread_only:
            notifications = notifications.filter(is_read=False)
        
        return notifications[:limit]
    
    @staticmethod
    def get_unread_count(user):
        """
        Get count of unread notifications for a user.
        """
        return Notification.objects.filter(
            recipient=user,
            is_read=False
        ).count()


class EmailNotificationService:
    """
    Service for managing email notifications to super-admin.
    """
    
    @staticmethod
    def send_daily_summary():
        """
        Send daily summary email to super-admin.
        """
        # Get yesterday's data
        yesterday = timezone.now() - timezone.timedelta(days=1)
        
        # Collect summary data
        summary_data = EmailNotificationService._collect_daily_summary(yesterday)
        
        if not summary_data['has_activity']:
            return  # No activity to report
        
        # Create email content
        subject = f"PRS Daily Summary - {yesterday.strftime('%Y-%m-%d')}"
        content = EmailNotificationService._render_daily_summary(summary_data)
        
        # Send email
        superadmin_email = getattr(settings, 'SUPER_ADMIN_OTP_EMAIL', None)
        if superadmin_email:
            email_log = EmailNotificationLog.objects.create(
                email_type='daily_summary',
                recipient_email=superadmin_email,
                subject=subject,
                content=content,
                notification_count=summary_data['total_notifications']
            )
            NotificationService._send_email_notification(email_log)
    
    @staticmethod
    def _collect_daily_summary(date):
        """
        Collect daily activity summary data.
        """
        from clients.models import Client
        from deals.models import Deal
        from authentication.models import User
        from organization.models import Organization
        
        start_date = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = start_date + timezone.timedelta(days=1)
        
        return {
            'date': date,
            'new_organizations': Organization.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'new_clients': Client.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'new_deals': Deal.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'new_users': User.objects.filter(
                date_joined__range=[start_date, end_date]
            ).count(),
            'total_notifications': Notification.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'has_activity': True  # Will be set based on actual data
        }
    
    @staticmethod
    def _render_daily_summary(data):
        """
        Render daily summary email content.
        """
        return f"""
        Payment Receiving System (PRS) - Daily Activity Summary
        Date: {data['date'].strftime('%Y-%m-%d')}
        
        📊 Activity Overview:
        • New Organizations: {data['new_organizations']}
        • New Clients: {data['new_clients']}
        • New Deals: {data['new_deals']}
        • New Users: {data['new_users']}
        • Total Notifications: {data['total_notifications']}
        
        This summary covers all activities across all organizations in the PRS system.
        
        ---
        Automated Daily Report from PRS System
        Generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """ 