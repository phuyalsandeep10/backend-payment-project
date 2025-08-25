"""
URL configuration for background task processing endpoints
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .background_task_views import BackgroundTaskViewSet, AutomatedProcessViewSet

# Create router for background task endpoints
router = DefaultRouter()
router.register(r'background-tasks', BackgroundTaskViewSet, basename='background-tasks')
router.register(r'automated-processes', AutomatedProcessViewSet, basename='automated-processes')

urlpatterns = [
    path('api/', include(router.urls)),
]

# Additional URL patterns for specific background task endpoints
background_task_patterns = [
    # Background task management
    path('api/background-tasks/queue-deal-processing/', 
         BackgroundTaskViewSet.as_view({'post': 'queue_deal_processing'}),
         name='queue-deal-processing'),
    
    path('api/background-tasks/queue-file-processing/', 
         BackgroundTaskViewSet.as_view({'post': 'queue_file_processing'}),
         name='queue-file-processing'),
    
    path('api/background-tasks/send-notification/', 
         BackgroundTaskViewSet.as_view({'post': 'send_notification'}),
         name='send-notification'),
    
    path('api/background-tasks/<str:pk>/status/', 
         BackgroundTaskViewSet.as_view({'get': 'get_task_status'}),
         name='task-status'),
    
    path('api/background-tasks/monitor/', 
         BackgroundTaskViewSet.as_view({'get': 'monitor_tasks'}),
         name='monitor-tasks'),
    
    # Automated business processes
    path('api/automated-processes/trigger-verification-reminders/', 
         AutomatedProcessViewSet.as_view({'post': 'trigger_verification_reminders'}),
         name='trigger-verification-reminders'),
    
    path('api/automated-processes/trigger-commission-calculation/', 
         AutomatedProcessViewSet.as_view({'post': 'trigger_commission_calculation'}),
         name='trigger-commission-calculation'),
    
    path('api/automated-processes/generate-audit-report/', 
         AutomatedProcessViewSet.as_view({'post': 'generate_audit_report'}),
         name='generate-audit-report'),
    
    path('api/automated-processes/trigger-cleanup/', 
         AutomatedProcessViewSet.as_view({'post': 'trigger_cleanup'}),
         name='trigger-cleanup'),
    
    path('api/automated-processes/process-status/', 
         AutomatedProcessViewSet.as_view({'get': 'get_process_status'}),
         name='process-status'),
    
    path('api/automated-processes/system-health/', 
         AutomatedProcessViewSet.as_view({'get': 'get_system_health'}),
         name='system-health'),
    
    path('api/automated-processes/audit-report/', 
         AutomatedProcessViewSet.as_view({'get': 'get_audit_report'}),
         name='get-audit-report'),
]

urlpatterns.extend(background_task_patterns)