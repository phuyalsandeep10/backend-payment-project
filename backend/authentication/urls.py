from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import LoginView, SuperAdminLoginView, SuperAdminVerifyOTPView, UserViewSet, UserSessionViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'sessions', UserSessionViewSet, basename='usersession')

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('', include(router.urls)),
    path('super-admin/login/', SuperAdminLoginView.as_view(), name='super-admin-login'),
    path('super-admin/verify/', SuperAdminVerifyOTPView.as_view(), name='super-admin-verify'),
]
