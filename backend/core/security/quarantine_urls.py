"""
URL configuration for quarantine management
Task 1.2.2 Implementation - Quarantine review workflow URLs
"""

from django.urls import path
from . import quarantine_views

app_name = 'quarantine'

urlpatterns = [
    # Web interface
    path('dashboard/', quarantine_views.quarantine_dashboard, name='dashboard'),
    
    # API endpoints
    path('api/files/', quarantine_views.list_quarantined_files, name='api_list_files'),
    path('api/files/<str:file_id>/', quarantine_views.get_quarantine_details, name='api_file_details'),
    path('api/files/<str:file_id>/restore/', quarantine_views.restore_quarantined_file, name='api_restore_file'),
    path('api/files/<str:file_id>/delete/', quarantine_views.delete_quarantined_file, name='api_delete_file'),
    path('api/cleanup/', quarantine_views.cleanup_old_quarantine_files, name='api_cleanup'),
    path('api/stats/', quarantine_views.quarantine_stats, name='api_stats'),
]