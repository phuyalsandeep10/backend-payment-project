from django.urls import path, re_path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import (
    UserViewSet,
    UserProfileViewSet
)

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'profile', UserProfileViewSet, basename='user-profile')

app_name = 'authentication'

urlpatterns = [
    path('', include(router.urls)),
    # ==================== AUTHENTICATION ENDPOINTS ====================
    re_path(r'^login/?$', views.direct_login_view, name='direct_login'),
    re_path(r'^register/?$', views.register_view, name='register'),
    re_path(r'^logout/?$', views.logout_view, name='logout'),
    
    # ==================== PASSWORD MANAGEMENT ====================
    re_path(r'^password/change/?$', views.password_change_view, name='password_change'),
    
    # ==================== USER PROFILE ====================
    re_path(r'^profile/?$', views.user_profile_view, name='profile'),
    re_path(r'^profile/update/?$', views.user_profile_update_view, name='profile_update'),
]
