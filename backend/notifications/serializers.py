from rest_framework import serializers
from .models import Notification, NotificationSettings, NotificationTemplate

class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for Notification model."""
    
    recipient_email = serializers.CharField(source='recipient.email', read_only=True)
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    
    class Meta:
        model = Notification
        fields = [
            'id', 'title', 'message', 'notification_type', 'priority', 'category',
            'recipient_email', 'organization_name', 'is_read', 'read_at',
            'related_object_type', 'related_object_id', 'action_url', 'created_at'
        ]
        read_only_fields = ['id', 'created_at', 'recipient_email', 'organization_name']

class NotificationSettingsSerializer(serializers.ModelSerializer):
    """Serializer for NotificationSettings model."""
    
    user_email = serializers.CharField(source='user.email', read_only=True)
    
    # Map frontend camelCase to backend snake_case
    desktopNotification = serializers.BooleanField(source='desktop_notification', required=False)
    unreadNotificationBadge = serializers.BooleanField(source='unread_notification_badge', required=False)
    pushNotificationTimeout = serializers.CharField(source='push_notification_timeout', required=False)
    communicationEmails = serializers.BooleanField(source='communication_emails', required=False)
    announcementsUpdates = serializers.BooleanField(source='announcements_updates', required=False)
    allNotificationSounds = serializers.BooleanField(source='all_notification_sounds', required=False)

    class Meta:
        model = NotificationSettings
        fields = [
            'id', 'user', 'user_email', 'enable_client_notifications', 'enable_deal_notifications',
            'enable_user_management_notifications', 'enable_team_notifications',
            'enable_project_notifications', 'enable_commission_notifications',
            'enable_system_notifications', 'min_priority', 'auto_mark_read_days',
            'created_at', 'updated_at',
            # Add new frontend-facing fields
            'desktopNotification', 'unreadNotificationBadge', 'pushNotificationTimeout',
            'communicationEmails', 'announcementsUpdates', 'allNotificationSounds'
        ]
        read_only_fields = ['id', 'user', 'user_email', 'created_at', 'updated_at']

class NotificationTemplateSerializer(serializers.ModelSerializer):
    """Serializer for NotificationTemplate model."""
    
    class Meta:
        model = NotificationTemplate
        fields = [
            'id', 'notification_type', 'title_template', 'message_template',
            'available_variables', 'is_active', 'created_at', 'updated_at',
            'created_by', 'updated_by'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'created_by', 'updated_by'
        ]

class MarkAsReadSerializer(serializers.Serializer):
    """Serializer for marking notifications as read."""
    
    notification_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="List of notification IDs to mark as read. If empty, marks all unread notifications."
    )

class NotificationStatsSerializer(serializers.Serializer):
    """Serializer for notification statistics."""
    
    total_notifications = serializers.IntegerField()
    unread_count = serializers.IntegerField()
    by_type = serializers.DictField()
    by_priority = serializers.DictField()
    recent_notifications = NotificationSerializer(many=True) 