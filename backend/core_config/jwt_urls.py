"""
JWT Authentication URL Configuration
"""

from django.urls import path
from . import jwt_views

urlpatterns = [
    # JWT Authentication endpoints
    path('jwt/login/', jwt_views.jwt_login, name='jwt_login'),
    path('jwt/verify-otp/', jwt_views.jwt_verify_otp, name='jwt_verify_otp'),
    path('jwt/refresh/', jwt_views.jwt_refresh, name='jwt_refresh'),
    path('jwt/logout/', jwt_views.jwt_logout, name='jwt_logout'),
    path('jwt/logout-all/', jwt_views.jwt_logout_all, name='jwt_logout_all'),
    path('jwt/change-password/', jwt_views.jwt_change_password, name='jwt_change_password'),
    path('jwt/profile/', jwt_views.jwt_user_profile, name='jwt_user_profile'),
    
    # Session Management endpoints
    path('jwt/sessions/', jwt_views.jwt_user_sessions, name='jwt_user_sessions'),
    path('jwt/sessions/invalidate/', jwt_views.jwt_invalidate_session, name='jwt_invalidate_session'),
    path('jwt/sessions/statistics/', jwt_views.jwt_session_statistics, name='jwt_session_statistics'),
]