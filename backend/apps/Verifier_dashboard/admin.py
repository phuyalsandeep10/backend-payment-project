from django.contrib import admin
from .models import AuditLogs

@admin.register(AuditLogs)
class AuditLogsAdmin(admin.ModelAdmin):
    list_display = ['action', 'user', 'timestamp', 'organization']
    list_filter = ['action', 'timestamp', 'organization']
    search_fields = ['action', 'user__username', 'details']
    readonly_fields = ['timestamp']
    ordering = ['-timestamp']
