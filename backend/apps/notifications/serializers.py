from rest_framework import serializers
from .models import Notification, NotificationSettings, NotificationTemplate

class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for Notification model."""
    
    recipient_email = serializers.CharField(source='recipient.email', read_only=True)
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    
    # Map backend snake_case to frontend camelCase
    notificationType = serializers.CharField(source='notification_type', read_only=True)
    relatedObjectType = serializers.CharField(source='related_object_type', read_only=True)
    relatedObjectId = serializers.IntegerField(source='related_object_id', read_only=True)
    actionUrl = serializers.URLField(source='action_url', read_only=True)
    isRead = serializers.BooleanField(source='is_read', read_only=True)
    readAt = serializers.DateTimeField(source='read_at', read_only=True)
    createdAt = serializers.DateTimeField(source='created_at', read_only=True)
    updatedAt = serializers.DateTimeField(source='updated_at', read_only=True)
    
    class Meta:
        model = Notification
        fields = [
            'id', 'title', 'message', 'notificationType', 'priority', 'category',
            'recipient_email', 'organization_name', 'isRead', 'readAt',
            'relatedObjectType', 'relatedObjectId', 'actionUrl', 'createdAt', 'updatedAt'
        ]
        read_only_fields = ['id', 'createdAt', 'updatedAt', 'recipient_email', 'organization_name']

class NotificationSettingsSerializer(serializers.ModelSerializer):
    """Serializer for NotificationSettings model."""
    
    user_email = serializers.CharField(source='user.email', read_only=True)
    
    # Frontend camelCase fields (read/write)
    desktopNotification = serializers.BooleanField(source='desktop_notification', required=False)
    unreadNotificationBadge = serializers.BooleanField(source='unread_notification_badge', required=False)
    pushNotificationTimeout = serializers.CharField(source='push_notification_timeout', required=False)
    communicationEmails = serializers.BooleanField(source='communication_emails', required=False)
    announcementsUpdates = serializers.BooleanField(source='announcements_updates', required=False)
    allNotificationSounds = serializers.BooleanField(source='all_notification_sounds', required=False)
    
    # Legacy backend fields for frontend compatibility (for both read and write)
    notification_timeout = serializers.CharField(source='push_notification_timeout', required=False)
    enable_email_notifications = serializers.BooleanField(source='communication_emails', required=False)
    enable_marketing_emails = serializers.BooleanField(source='announcements_updates', required=False)
    enable_sound_notifications = serializers.BooleanField(source='all_notification_sounds', required=False)

    class Meta:
        model = NotificationSettings
        fields = [
            'id', 'user', 'user_email', 'enable_client_notifications', 'enable_deal_notifications',
            'enable_user_management_notifications', 'enable_team_notifications',
            'enable_project_notifications', 'enable_commission_notifications',
            'enable_system_notifications', 'min_priority', 'auto_mark_read_days',
            'created_at', 'updated_at',
            # Frontend camelCase fields
            'desktopNotification', 'unreadNotificationBadge', 'pushNotificationTimeout',
            'communicationEmails', 'announcementsUpdates', 'allNotificationSounds',
            # Legacy compatibility fields
            'notification_timeout', 'enable_email_notifications', 'enable_marketing_emails', 'enable_sound_notifications'
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
    
    # Map to frontend camelCase
    totalNotifications = serializers.IntegerField(source='total_notifications', read_only=True)
    unreadCount = serializers.IntegerField(source='unread_count', read_only=True)
    byType = serializers.DictField(source='by_type', read_only=True)
    byPriority = serializers.DictField(source='by_priority', read_only=True)
    recentNotifications = NotificationSerializer(source='recent_notifications', many=True, read_only=True) 