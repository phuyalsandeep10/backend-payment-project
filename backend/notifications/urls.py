from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    NotificationViewSet, NotificationSettingsViewSet, 
    EmailNotificationLogViewSet, NotificationTemplateViewSet,
    NotificationDashboardView, TestNotificationView
)

# Create router and register viewsets
router = DefaultRouter()
router.register(r'notifications', NotificationViewSet, basename='notification')
router.register(r'settings', NotificationSettingsViewSet, basename='notification-settings')
router.register(r'email-logs', EmailNotificationLogViewSet, basename='email-logs')
router.register(r'templates', NotificationTemplateViewSet, basename='notification-templates')

urlpatterns = [
    # Router URLs
    path('', include(router.urls)),
    
    # Additional utility endpoints
    path('dashboard/', NotificationDashboardView.as_view(), name='notification-dashboard'),
    path('test/', TestNotificationView.as_view(), name='test-notification'),
] 