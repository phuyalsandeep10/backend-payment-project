from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'notifications'

# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'notifications', views.NotificationViewSet, basename='notification')
router.register(r'notification-settings', views.NotificationSettingsViewSet, basename='notification-settings')
router.register(r'notification-admin', views.NotificationAdminViewSet, basename='notification-admin')

# The API URLs are now determined automatically by the router.
urlpatterns = [
    path('', include(router.urls)),
] 