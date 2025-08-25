from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import json

from apps.clients.models import Client
from apps.deals.models import Deal, Payment
from apps.organization.models import Organization
from apps.permissions.models import Role
from apps.team.models import Team
from apps.project.models import Project
from apps.commission.models import Commission
from apps.notifications.models import Notification
from .services import NotificationService
from apps.notifications.serializers import NotificationSerializer
from .group_utils import sync_group_manager

User = get_user_model()

@receiver(post_save, sender=Notification)
def send_live_notification(sender, instance, created, **kwargs):
    """Send live notification to the user via WebSocket when a notification is created."""
    if created:
        try:
            # Serialize the notification data
            serializer = NotificationSerializer(instance)
            notification_data = serializer.data
            
            # Send to the specific user
            sync_group_manager.send_to_user(instance.recipient.id, notification_data)
            
            print(f"[NotificationSignal] Sent notification {instance.id} to user {instance.recipient.id}")
        except Exception as e:
            print(f"[NotificationSignal] Error sending notification {instance.id}: {e}")

# =============================================================================
# CLIENT NOTIFICATIONS
# =============================================================================

@receiver(post_save, sender=Client)
def notify_new_client(sender, instance, created, **kwargs):
    """Send notification when a new client is created."""
    if created:
        # Notify organization users (admins and relevant roles)
        NotificationService.notify_role_based_users(
            organization=instance.organization,
            notification_type='client_created',
            title=f'New Client Added: {instance.client_name}',
            message=f'A new client "{instance.client_name}" has been added by {instance.created_by.get_full_name() or instance.created_by.email}.',
            target_roles=['admin', 'manager', 'team_lead'],
            priority='medium',
            category='business',
            related_object_type='client',
            related_object_id=instance.id,
            send_email_to_superadmin=True
        )

# =============================================================================
# DEAL NOTIFICATIONS  
# =============================================================================

def create_notification(recipients, title, message, notification_type, organization, created_by=None):
    """Helper function to create notifications."""
    for recipient in recipients:
        Notification.objects.create(
            recipient=recipient,
            title=title,
            message=message,
            notification_type=notification_type,
            organization=organization,
        )

@receiver(post_save, sender=Deal)
def notify_deal_changes(sender, instance, created, **kwargs):
    """Send notification when a deal is created or updated."""
    if created:
        log_message = f"Deal '{instance.deal_id}' created by {instance.created_by.username}."
        recipients = User.objects.filter(Q(role__name='Admin') | Q(is_superuser=True), organization=instance.organization)
        
        create_notification(
            recipients=recipients,
            title=f'New Deal: {instance.client.client_name}',
            message=log_message,
            notification_type='deal_created',
            organization=instance.organization,
            created_by=instance.created_by
        )
    else:
        # Log activity for deal updates
        try:
            old_instance = Deal.objects.get(pk=instance.pk)
            if old_instance.verification_status != instance.verification_status:
                log_message = f"Deal '{instance.deal_id}' status changed to {instance.verification_status} by system/user."
                
                # Notify the user who created the deal
                create_notification(
                    recipients=[instance.created_by],
                    title=f'Deal Status Updated: {instance.client.client_name}',
                    message=log_message,
                    notification_type='deal_status_change',
                    organization=instance.organization,
                    created_by=None  # System-generated
                )
        except Deal.DoesNotExist:
            pass

@receiver(post_save, sender=Payment)
def notify_payment_received(sender, instance, created, **kwargs):
    """Send notification when a payment is received."""
    if created:
        deal = instance.deal
        NotificationService.notify_role_based_users(
            organization=deal.organization,
            notification_type='payment_received',
            title=f'Payment Received: ${instance.received_amount}',
            message=f'Payment of ${instance.received_amount} received for deal "{deal.deal_id}" on {instance.payment_date}.',
            target_roles=['admin', 'manager', 'team_lead', 'verifier'],
            priority='high',
            category='business',
            related_object_type='payment',
            related_object_id=instance.id,
            send_email_to_superadmin=True
        )

# =============================================================================
# USER MANAGEMENT NOTIFICATIONS
# =============================================================================

@receiver(post_save, sender=User)
def notify_new_user(sender, instance, created, **kwargs):
    """Send notification when a new user is created."""
    if created and instance.organization:
        # Don't notify for superuser creation
        if not instance.is_superuser:
            NotificationService.notify_role_based_users(
                organization=instance.organization,
                notification_type='user_created',
                title=f'New User Added: {instance.get_full_name() or instance.email}',
                message=f'A new user "{instance.get_full_name() or instance.email}" with role "{instance.role.name if instance.role else "No role"}" has been added to the organization.',
                target_roles=['admin', 'manager'],
                priority='medium',
                category='user_management',
                related_object_type='user',
                related_object_id=instance.id,
                send_email_to_superadmin=True
            )

@receiver(post_save, sender=Role)
def notify_new_role(sender, instance, created, **kwargs):
    """Send notification when a new role is created."""
    if created and instance.organization:
        NotificationService.notify_role_based_users(
            organization=instance.organization,
            notification_type='role_created',
            title=f'New Role Created: {instance.name}',
            message=f'A new role "{instance.name}" has been created in the organization with {instance.permissions.count()} permissions.',
            target_roles=['admin'],
            priority='medium',
            category='user_management',
            related_object_type='role',
            related_object_id=instance.id,
            send_email_to_superadmin=True
        )

# =============================================================================
# TEAM NOTIFICATIONS
# =============================================================================

@receiver(post_save, sender=Team)
def notify_new_team(sender, instance, created, **kwargs):
    """Send notification when a new team is created."""
    if created:
        team_lead_name = instance.team_lead.get_full_name() or instance.team_lead.email if instance.team_lead else "Not assigned"
        
        NotificationService.notify_role_based_users(
            organization=instance.organization,
            notification_type='team_created',
            title=f'New Team Created: {instance.name}',
            message=f'A new team "{instance.name}" has been created with team lead: {team_lead_name}.',
            target_roles=['admin', 'manager'],
            priority='medium',
            category='user_management',
            related_object_type='team',
            related_object_id=instance.id,
            send_email_to_superadmin=True
        )

# =============================================================================
# PROJECT NOTIFICATIONS
# =============================================================================

@receiver(post_save, sender=Project)
def notify_new_project(sender, instance, created, **kwargs):
    """Send notification when a new project is created."""
    if created:
        # Since Project is not directly linked to an Organization, we find it via the created_by user
        if instance.created_by and instance.created_by.organization:
            NotificationService.notify_role_based_users(
                organization=instance.created_by.organization,
                notification_type='project_created',
                title=f'New Project Created: {instance.name}',
                message=f'A new project "{instance.name}" has been created in the organization by {instance.created_by.get_full_name()}.',
                target_roles=['admin', 'manager'],
                priority='medium',
                category='business',
                related_object_type='project',
                related_object_id=instance.id,
                send_email_to_superadmin=False # Superadmin will get a different notification
            )

# =============================================================================
# COMMISSION NOTIFICATIONS
# =============================================================================

@receiver(post_save, sender=Commission)
def notify_new_commission(sender, instance, created, **kwargs):
    """Send notification when a new commission is created."""
    if created:
        NotificationService.notify_role_based_users(
            organization=instance.organization,
            notification_type='commission_created',
            title=f'New Commission: {instance.user.get_full_name() or instance.user.email}',
            message=f'A commission of ${instance.total_receivable:,.2f} has been calculated for {instance.user.get_full_name()}.',
            target_roles=['admin', 'manager'],
            priority='medium',
            category='business',
            related_object_type='commission',
            related_object_id=instance.id,
            send_email_to_superadmin=True
        )

# =============================================================================
# ORGANIZATION NOTIFICATIONS
# =============================================================================

@receiver(post_save, sender=Organization)
def notify_new_organization(sender, instance, created, **kwargs):
    """Send notification when a new organization is created."""
    if created:
        # This goes directly to super-admin only
        NotificationService.notify_role_based_users(
            organization=None,  # No specific org context for superadmins
            notification_type='new_organization',
            title=f'New Organization Registered: {instance.name}',
            message=f'A new organization "{instance.name}" has been registered in the PRS system.',
            target_roles=['super_admin'],  # Custom filter in the service for this role
            priority='high',
            category='system',
            related_object_type='organization',
            related_object_id=instance.id,
            send_email_to_superadmin=True
        )

# =============================================================================
# ENHANCED GROUP-BASED NOTIFICATION SIGNALS
# =============================================================================

def send_role_broadcast_notification(org_id, role_names, title, message, notification_type='system_alert', priority='medium'):
    """
    Send broadcast notification to specific roles within an organization
    without creating individual notification records.
    """
    from django.utils import timezone
    
    notification_data = {
        'title': title,
        'message': message,
        'notification_type': notification_type,
        'priority': priority,
        'category': 'broadcast',
        'is_broadcast': True,
        'created_at': timezone.now().isoformat(),
        'organization_id': org_id
    }
    
    sync_group_manager.send_to_roles(org_id, role_names, notification_data)
    print(f"[BroadcastSignal] Sent {notification_type} to roles {role_names} in org {org_id}")

def send_organization_broadcast(org_id, title, message, notification_type='system_alert', priority='medium'):
    """
    Send broadcast notification to all users in an organization
    without creating individual notification records.
    """
    from django.utils import timezone
    
    notification_data = {
        'title': title,
        'message': message,
        'notification_type': notification_type,
        'priority': priority,
        'category': 'broadcast',
        'is_broadcast': True,
        'created_at': timezone.now().isoformat(),
        'organization_id': org_id
    }
    
    sync_group_manager.send_org_broadcast(org_id, notification_data)
    print(f"[BroadcastSignal] Sent {notification_type} broadcast to org {org_id}")

def send_system_broadcast(title, message, notification_type='system_alert', priority='high'):
    """
    Send system-wide broadcast notification to all connected users
    without creating individual notification records.
    """
    from django.utils import timezone
    
    notification_data = {
        'title': title,
        'message': message,
        'notification_type': notification_type,
        'priority': priority,
        'category': 'broadcast',
        'is_broadcast': True,
        'created_at': timezone.now().isoformat(),
        'system_wide': True
    }
    
    sync_group_manager.send_system_broadcast(notification_data)
    print(f"[BroadcastSignal] Sent system-wide {notification_type} broadcast")

# Example usage functions that can be called from management commands or admin actions
def notify_system_maintenance(start_time, duration_minutes):
    """Notify all users about scheduled system maintenance"""
    send_system_broadcast(
        title="Scheduled System Maintenance",
        message=f"System maintenance is scheduled to start at {start_time} and will last approximately {duration_minutes} minutes. Please save your work.",
        notification_type="system_maintenance",
        priority="high"
    )

def notify_organization_announcement(org_id, title, message):
    """Send announcement to all users in an organization"""
    send_organization_broadcast(
        org_id=org_id,
        title=title,
        message=message,
        notification_type="organization_announcement",
        priority="medium"
    ) 

 
