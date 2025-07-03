from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # ==================== AUTHENTICATION ENDPOINTS ====================
    path('login/', views.login_view, name='login'),
    path('login/enhanced/', views.user_login_view, name='enhanced_login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    
    # ==================== PASSWORD MANAGEMENT ====================
    path('password/reset/', views.password_reset_request_view, name='password_reset'),
    path('password/change/', views.password_change_view, name='password_change'),
    
    # ==================== USER PROFILE ====================
    path('profile/', views.user_profile_view, name='profile'),
    path('profile/update/', views.user_profile_update_view, name='profile_update'),
    path('sessions/', views.user_sessions_view, name='sessions'),
    
    # ==================== SUPER ADMIN ====================
    path('super-admin/login/', views.super_admin_login_view, name='super_admin_login'),
    path('super-admin/verify/', views.super_admin_verify_view, name='super_admin_verify'),
]
