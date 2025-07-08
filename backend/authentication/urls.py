from django.urls import path, re_path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import (
    UserViewSet,
    UserProfileView
)

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
# router.register(r'profile', UserProfileViewSet, basename='user-profile') # This is redundant and conflicts with the UserProfileView below

app_name = 'authentication'

urlpatterns = [
    path('', include(router.urls)),
    # ==================== AUTHENTICATION ENDPOINTS ====================
    re_path(r'^login/?$', views.direct_login_view, name='direct_login'),
    re_path(r'^register/?$', views.register_view, name='register'),
    re_path(r'^logout/?$', views.logout_view, name='logout'),
    
    # ==================== PASSWORD MANAGEMENT ====================
    path('password/change/', views.password_change_view, name='password_change'),
    
    # ==================== USER PROFILE ====================
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('user/set-sales-target/', views.set_sales_target_view, name='set_sales_target'),
]
