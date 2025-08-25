"""
URL routing for enhanced file upload with background processing
"""

from django.urls import path
from . import enhanced_file_upload_views

app_name = 'enhanced_file_upload'

urlpatterns = [
    # Enhanced file upload with background processing
    path(
        'upload/',
        enhanced_file_upload_views.EnhancedFileUploadView.as_view(),
        name='enhanced-file-upload'
    ),
    
    # File processing status check
    path(
        'status/',
        enhanced_file_upload_views.FileProcessingStatusView.as_view(),
        name='file-processing-status'
    ),
    
    # Background task monitoring (admin only)
    path(
        'monitoring/',
        enhanced_file_upload_views.BackgroundTaskMonitoringView.as_view(),
        name='background-task-monitoring'
    ),
]