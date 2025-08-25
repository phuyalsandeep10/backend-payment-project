from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter

# Import from modular view files
from .user_views import UserViewSet
from .auth_views import (
    login_view, logout_view, verify_otp_view, register_view,
    super_admin_login_view, super_admin_verify_view,
    org_admin_login_view, org_admin_verify_view,
    password_change_view, password_change_with_token_view,
    PasswordChangeWithTokenView, password_change_with_token_django_view,
    health_check, login_stats_view
)
from .session_views import UserSessionViewSet, test_email_outbox_view
from .profile_views import UserProfileView, UserNotificationPreferencesView, set_sales_target_view, test_upload_view
from .password_views import (
    password_policy_dashboard,
    validate_password_strength,
    password_analytics,
    force_password_reset_organization,
    send_password_notification_bulk,
    send_password_notification_single,
)

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

session_router = DefaultRouter()
session_router.register(r'sessions', UserSessionViewSet, basename='session')

app_name = 'authentication'

urlpatterns = [
    # ==================== USER MANAGEMENT ====================
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('test-upload/', test_upload_view, name='test_upload'),
    path('password/change/', password_change_view, name='password_change'),
    path('users/notification-preferences/', UserNotificationPreferencesView.as_view(), name='notification_prefs'),
    path('users/set-sales-target/', set_sales_target_view, name='set_sales_target'),
    path('users/login-stats/', login_stats_view, name='login_stats'),
    path('test-email-outbox/', test_email_outbox_view, name='test_email_outbox'),
    # Routers for viewsets
    path('', include(router.urls)),
    path('', include(session_router.urls)),
    
    # ==================== AUTHENTICATION ENDPOINTS ====================
    # Login endpoints
    re_path(r'^login/?$', login_view, name='login'),
    re_path(r'^login/verify-otp/?$', verify_otp_view, name='verify_otp'),
    
    # Super Admin login endpoints
    re_path(r'^login/super-admin/?$', super_admin_login_view, name='super_admin_login'),
    re_path(r'^login/super-admin/verify/?$', super_admin_verify_view, name='super_admin_verify'),
    
    # Org Admin login endpoints
    re_path(r'^login/org-admin/?$', org_admin_login_view, name='org_admin_login'),
    re_path(r'^login/org-admin/verify/?$', org_admin_verify_view, name='org_admin_verify'),
    
    # Registration & Logout
    re_path(r'^register/?$', register_view, name='register'),
    re_path(r'^logout/?$', logout_view, name='logout'),
    
    # Password change with temporary token
    re_path(r'^change-password/?$', password_change_with_token_django_view, name='change_password_temp'),
    
    # ==================== PASSWORD MANAGEMENT ====================
    path('password/policy/dashboard/', password_policy_dashboard, name='password_policy_dashboard'),
    path('password/validate/', validate_password_strength, name='validate_password_strength'),
    path('password/analytics/', password_analytics, name='password_analytics'),
    path('password/force-reset-org/', force_password_reset_organization, name='force_password_reset_org'),
    
    # Background Email Notifications for Password Management
    path('password/notifications/bulk/', send_password_notification_bulk, name='password_notification_bulk'),
    path('password/notifications/<int:user_id>/', send_password_notification_single, name='password_notification_single'),
    
    # ==================== HEALTH CHECK ====================
    path('health-check/', health_check, name='health_check'),
]
