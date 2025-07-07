from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    LoginView, 
    LogoutView,
    RefreshTokenView,
    ForgotPasswordView,
    ResetPasswordView,
    VerifyEmailView,
    SuperAdminLoginView, 
    SuperAdminVerifyOTPView, 
    UserViewSet, 
    UserSessionViewSet,
    OrgAdminLoginView,
    OrgAdminVerifyOTPView,
    ChangePasswordView
)

user_router = DefaultRouter()
user_router.register(r'users', UserViewSet, basename='user')

session_router = DefaultRouter()
session_router.register(r'sessions', UserSessionViewSet, basename='usersession')

urlpatterns = [
    path('', include(user_router.urls)),
    path('', include(session_router.urls)),
    # Authentication endpoints
    path('login/', LoginView.as_view(), name='login'),
    path('login', LoginView.as_view(), name='login-no-slash'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logout', LogoutView.as_view(), name='logout-no-slash'),
    path('refresh/', RefreshTokenView.as_view(), name='refresh-token'),
    path('refresh', RefreshTokenView.as_view(), name='refresh-token-no-slash'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('forgot-password', ForgotPasswordView.as_view(), name='forgot-password-no-slash'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('reset-password', ResetPasswordView.as_view(), name='reset-password-no-slash'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('verify-email', VerifyEmailView.as_view(), name='verify-email-no-slash'),
    # Change password using temporary token
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('change-password', ChangePasswordView.as_view(), name='change-password-no-slash'),
    # Super admin endpoints
    path('super-admin/login/', SuperAdminLoginView.as_view(), name='super-admin-login'),
    path('super-admin/verify/', SuperAdminVerifyOTPView.as_view(), name='super-admin-verify'),
    path('org-admin/login/', OrgAdminLoginView.as_view(), name='org-admin-login'),
    path('org-admin/verify/', OrgAdminVerifyOTPView.as_view(), name='org-admin-verify'),
]
