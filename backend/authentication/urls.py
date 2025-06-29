from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    LoginView, 
    LogoutView,
    SuperAdminLoginView, 
    SuperAdminVerifyOTPView, 
    UserViewSet, 
    UserSessionViewSet
)

user_router = DefaultRouter()
user_router.register(r'users', UserViewSet, basename='user')

session_router = DefaultRouter()
session_router.register(r'sessions', UserSessionViewSet, basename='usersession')

urlpatterns = [
    path('', include(user_router.urls)),
    path('', include(session_router.urls)),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('super-admin/login/', SuperAdminLoginView.as_view(), name='super-admin-login'),
    path('super-admin/verify/', SuperAdminVerifyOTPView.as_view(), name='super-admin-verify'),
]
