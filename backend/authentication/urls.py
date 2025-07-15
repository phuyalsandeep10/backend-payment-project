from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter
from . import views
from .views import (
    UserViewSet,
    UserProfileView,
    UserNotificationPreferencesView,
    health_check,
    UserSessionViewSet,
    password_change_view,
    test_email_outbox_view,
)

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

session_router = DefaultRouter()
session_router.register(r'sessions', UserSessionViewSet, basename='session')

app_name = 'authentication'

urlpatterns = [
    # ==================== USER MANAGEMENT ====================
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('password/change/', password_change_view, name='password_change'),
    path('users/notification-preferences/', UserNotificationPreferencesView.as_view(), name='notification_prefs'),
    path('users/set-sales-target/', views.set_sales_target_view, name='set_sales_target'),
    path('users/login-stats/', views.login_stats_view, name='login_stats'),
    path('test-email-outbox/', test_email_outbox_view, name='test_email_outbox'),
    # Routers for viewsets
    path('', include(router.urls)),
    path('', include(session_router.urls)),
    
    # ==================== AUTHENTICATION ENDPOINTS ====================
    # Login endpoints
    re_path(r'^login/?$', views.login_view, name='login'),
    re_path(r'^login/verify-otp/?$', views.verify_otp_view, name='verify_otp'),
    
    # Registration & Logout
    re_path(r'^register/?$', views.register_view, name='register'),
    re_path(r'^logout/?$', views.logout_view, name='logout'),
    
    # Password change with temporary token
    re_path(r'^change-password/?$', views.password_change_with_token_view, name='change_password_temp'),
    
    # ==================== HEALTH CHECK ====================
    path('health-check/', health_check, name='health_check'),
]
