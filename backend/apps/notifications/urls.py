from django.urls import path
from apps.notifications.views import (
    NotificationViewSet, 
    NotificationAdminViewSet, 
    TestNotificationView,
    NotificationDashboardView,
    NotificationPreferencesView,
    get_websocket_token
)
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'', NotificationViewSet, basename='notification')
router.register(r'admin', NotificationAdminViewSet, basename='notification-admin')

app_name = "notifications"
urlpatterns = [
    path('preferences/', NotificationPreferencesView.as_view(), name='notification-preferences'),
    path('dashboard/', NotificationDashboardView.as_view(), name='notification-dashboard'),
    path('test/', TestNotificationView.as_view(), name='notification-test'),
    path('websocket-token/', get_websocket_token, name='websocket-token'),
]

urlpatterns += router.urls 