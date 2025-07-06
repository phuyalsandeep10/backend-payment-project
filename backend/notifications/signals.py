from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from clients.models import Client
from deals.models import Deal, Payment
from organization.models import Organization
from permissions.models import Role
from team.models import Team
from project.models import Project
from commission.models import Commission
from .services import NotificationService
from django.db.models import Q
from notifications.models import Notification

User = get_user_model()

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
            title=f'New Commission Created: ${instance.converted_amount}',
            message=f'A new commission of ${instance.converted_amount} has been created for user {instance.user.get_full_name() or instance.user.email}.',
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