from django.urls import path
from .views import CustomAuthToken, SuperAdminLoginView, SuperAdminVerifyOTPView

urlpatterns = [
    path('login/', CustomAuthToken.as_view(), name='auth-token'),
    path('super-admin/login/', SuperAdminLoginView.as_view(), name='super-admin-login'),
    path('super-admin/verify/', SuperAdminVerifyOTPView.as_view(), name='super-admin-verify'),
]
