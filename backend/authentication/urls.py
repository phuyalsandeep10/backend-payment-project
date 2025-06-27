from django.urls import path, include
from .views import SuperAdminLoginView, SuperAdminVerifyOTPView, UserViewSet
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    path('', include(router.urls)),
    path('super-admin/login/', SuperAdminLoginView.as_view(), name='super-admin-login'),
    path('super-admin/verify/', SuperAdminVerifyOTPView.as_view(), name='super-admin-verify'),
]
