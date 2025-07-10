from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'notifications', views.NotificationViewSet, basename='notification')
router.register(r'notification-settings', views.NotificationSettingsViewSet, basename='notification-settings')
router.register(r'notification-admin', views.NotificationAdminViewSet, basename='notification-admin')

urlpatterns = [
    path('', include(router.urls)),
] 