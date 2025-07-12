from django.urls import path
from .views import (
    NotificationViewSet, 
    NotificationAdminViewSet, 
    TestNotificationView,
    NotificationDashboardView,
    NotificationPreferencesView
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
]

urlpatterns += router.urls 