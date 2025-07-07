from django.contrib import admin
from .models import User, UserNotificationPreferences

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role', 'organization', 'is_staff', 'is_superuser', 'address')
    list_filter = ('role', 'organization', 'is_staff', 'is_superuser')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('username',)

@admin.register(UserNotificationPreferences)
class UserNotificationPreferencesAdmin(admin.ModelAdmin):
    list_display = ('user', 'desktop_notifications', 'communication_emails', 'notification_sounds')
    list_filter = ('desktop_notifications', 'communication_emails', 'notification_sounds')
    search_fields = ('user__email', 'user__username')
    ordering = ('user__username',)
