from django.urls import path, re_path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import (
    UserViewSet,
    UserProfileView,
    UserNotificationPreferencesView,
    health_check,
    UserSessionViewSet,
    password_change_view,
)

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
# router.register(r'profile', UserProfileViewSet, basename='user-profile') # This is redundant and conflicts with the UserProfileView below

session_router = DefaultRouter()
session_router.register(r'sessions', UserSessionViewSet, basename='session')

app_name = 'authentication'

urlpatterns = [
    # Specific user-related actions must come BEFORE the generic router
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('users/profile/', UserProfileView.as_view(), name='profile_alias'),
    path('password/change/', password_change_view, name='password_change'),
    path('users/change_password/', password_change_view, name='password_change_alt'),
    path('users/notification_preferences/', UserNotificationPreferencesView.as_view(), name='notification_prefs'),
    path('user/set-sales-target/', views.set_sales_target_view, name='set_sales_target'),

    # Routers for viewsets
    path('', include(router.urls)),
    path('', include(session_router.urls)),
    
    # ==================== AUTHENTICATION ENDPOINTS ====================
    # Legacy direct login (development)
    re_path(r'^login/?$', views.direct_login_view, name='direct_login'),
    # OTP-based login for Super Admin and Org Admin
    re_path(r'^super-admin/login/?$', views.super_admin_login_view, name='super_admin_login'),
    re_path(r'^super-admin/verify/?$', views.super_admin_verify_view, name='super_admin_verify'),
    re_path(r'^org-admin/login/?$', views.org_admin_login_view, name='org_admin_login'),
    re_path(r'^org-admin/verify/?$', views.org_admin_verify_view, name='org_admin_verify'),
    re_path(r'^change-password/?$', views.password_change_with_token, name='change_password_temp'),
    re_path(r'^register/?$', views.register_view, name='register'),
    re_path(r'^logout/?$', views.logout_view, name='logout'),
    
    # ==================== HEALTH CHECK ====================
    path('health/', health_check, name='health_check'),
]
