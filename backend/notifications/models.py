from django.db import models
from django.conf import settings
from organization.models import Organization

class Notification(models.Model):
    """
    Model for in-system notifications shown to users.
    """
    
    # Notification Types
    TYPE_CHOICES = [
        ('client_created', 'New Client Created'),
        ('deal_created', 'New Deal Created'),
        ('deal_updated', 'Deal Updated'), 
        ('deal_status_changed', 'Deal Status Changed'),
        ('user_created', 'New User Created'),
        ('role_created', 'New Role Created'),
        ('team_created', 'New Team Created'),
        ('project_created', 'New Project Created'),
        ('commission_created', 'New Commission Created'),
        ('payment_received', 'Payment Received'),
        ('new_organization', 'New Organization Created'),
        ('system_alert', 'System Alert'),
        ('system_maintenance', 'System Maintenance'),
        ('organization_announcement', 'Organization Announcement'),
        ('test_system_broadcast', 'Test System Broadcast'),
        ('test_notification', 'Test Notification'),
    ]
    
    # Priority Levels
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('urgent', 'Urgent'),
    ]
    
    # Notification Categories
    CATEGORY_CHOICES = [
        ('business', 'Business Operations'),
        ('user_management', 'User Management'),
        ('system', 'System'),
        ('security', 'Security'),
    ]
    
    title = models.CharField(max_length=255)
    message = models.TextField()
    notification_type = models.CharField(max_length=50, choices=TYPE_CHOICES)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='medium')
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='business')
    
    # Recipients
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    
    # Status
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    related_object_type = models.CharField(max_length=100, null=True, blank=True)  # e.g., 'client', 'deal'
    related_object_id = models.PositiveIntegerField(null=True, blank=True)
    action_url = models.URLField(null=True, blank=True)  # Frontend URL for action
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['recipient', 'is_read']),
            models.Index(fields=['organization', 'created_at']),
            models.Index(fields=['notification_type']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.recipient.email}"
    
    def mark_as_read(self):
        """Mark notification as read"""
        from django.utils import timezone
        self.is_read = True
        self.read_at = timezone.now()
        self.save()


class NotificationSettings(models.Model):
    """
    User notification preferences and settings.
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notification_settings')
    
    # In-system notification preferences
    enable_client_notifications = models.BooleanField(default=True)
    enable_deal_notifications = models.BooleanField(default=True)
    enable_user_management_notifications = models.BooleanField(default=True)
    enable_team_notifications = models.BooleanField(default=True)
    enable_project_notifications = models.BooleanField(default=True)
    enable_commission_notifications = models.BooleanField(default=True)
    enable_system_notifications = models.BooleanField(default=True)

    # --- UI-friendly fields (Settings Page v2) ---
    desktop_notification = models.BooleanField(default=True)
    unread_notification_badge = models.BooleanField(default=False)
    push_notification_timeout = models.CharField(max_length=20, default="select")  # e.g. "15", "30", "never"
    communication_emails = models.BooleanField(default=True)
    announcements_updates = models.BooleanField(default=False)
    all_notification_sounds = models.BooleanField(default=True)
    
    # Priority filter (minimum priority to show)
    min_priority = models.CharField(
        max_length=20, 
        choices=Notification.PRIORITY_CHOICES, 
        default='low'
    )
    
    # Auto-mark as read after (in days, 0 = never)
    auto_mark_read_days = models.PositiveIntegerField(default=7)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Notification Settings - {self.user.email}"


class NotificationTemplate(models.Model):
    """
    Templates for different types of notifications.
    """
    notification_type = models.CharField(max_length=50, choices=Notification.TYPE_CHOICES, unique=True)
    title_template = models.CharField(max_length=255)
    message_template = models.TextField()
    
    # Template variables help text
    available_variables = models.TextField(
        help_text="List of available template variables (JSON format)",
        null=True, blank=True
    )
    
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_notification_templates'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='updated_notification_templates'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Template: {self.get_notification_type_display()}" 
