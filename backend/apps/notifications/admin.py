from django.contrib import admin
from django.utils.html import format_html
from .models import Notification, NotificationSettings, NotificationTemplate

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'recipient_email', 'notification_type', 'priority', 
        'category', 'is_read', 'organization_name', 'created_at'
    ]
    list_filter = [
        'notification_type', 'priority', 'category', 'is_read', 
        'organization', 'created_at'
    ]
    search_fields = [
        'title', 'message', 'recipient__email', 'recipient__username'
    ]
    readonly_fields = ['created_at', 'updated_at', 'read_at']
    raw_id_fields = ['recipient', 'organization']
    
    fieldsets = (
        ('Notification Details', {
            'fields': ('title', 'message', 'notification_type', 'priority', 'category')
        }),
        ('Recipients', {
            'fields': ('recipient', 'organization')
        }),
        ('Status', {
            'fields': ('is_read', 'read_at')
        }),
        ('Metadata', {
            'fields': ('related_object_type', 'related_object_id', 'action_url'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def recipient_email(self, obj):
        return obj.recipient.email
    recipient_email.short_description = 'Recipient'
    
    def organization_name(self, obj):
        return obj.organization.name if obj.organization else 'System'
    organization_name.short_description = 'Organization'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('recipient', 'organization')


@admin.register(NotificationSettings)
class NotificationSettingsAdmin(admin.ModelAdmin):
    list_display = [
        'user_email', 'enable_client_notifications', 'enable_deal_notifications',
        'enable_user_management_notifications', 'min_priority', 'auto_mark_read_days'
    ]
    list_filter = [
        'enable_client_notifications', 'enable_deal_notifications',
        'enable_user_management_notifications', 'min_priority'
    ]
    search_fields = ['user__email', 'user__username']
    readonly_fields = ['created_at', 'updated_at']
    raw_id_fields = ['user']
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('In-System Notifications', {
            'fields': (
                'enable_client_notifications', 'enable_deal_notifications',
                'enable_user_management_notifications', 'enable_team_notifications',
                'enable_project_notifications', 'enable_commission_notifications',
                'enable_system_notifications'
            )
        }),
        ('Preferences', {
            'fields': ('min_priority', 'auto_mark_read_days')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'


@admin.register(NotificationTemplate)
class NotificationTemplateAdmin(admin.ModelAdmin):
    list_display = [
        'notification_type', 'title_template_short', 'is_active', 'created_at'
    ]
    list_filter = ['notification_type', 'is_active', 'created_at']
    search_fields = ['title_template', 'message_template']
    readonly_fields = ['created_at', 'updated_at', 'created_by', 'updated_by']
    
    fieldsets = (
        ('Template Details', {
            'fields': ('notification_type', 'is_active')
        }),
        ('In-System Notification Templates', {
            'fields': ('title_template', 'message_template')
        }),
        ('Help', {
            'fields': ('available_variables',),
            'classes': ('collapse',)
        }),
        ('Audit', {
            'fields': ('created_by', 'updated_by'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def title_template_short(self, obj):
        return obj.title_template[:50] + '...' if len(obj.title_template) > 50 else obj.title_template
    title_template_short.short_description = 'Title Template' 