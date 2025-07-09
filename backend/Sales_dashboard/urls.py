from django.urls import path, include, re_path
from . import views

app_name = 'sales_dashboard'

urlpatterns = [
    # ==================== MAIN DASHBOARD ====================
    path('dashboard/', views.dashboard_view, name='dashboard'),
    
    # ==================== STREAK MANAGEMENT ====================
    path('streak/', views.streak_view, name='streak'),
    path('streak/leaderboard/', views.streak_leaderboard_view, name='leaderboard'),
    
    # ==================== PERFORMANCE TRACKING ====================
    path('standings/', views.standings_view, name='standings'),
    path('commission/', views.commission_overview_view, name='commission'),
    
    # ==================== CLIENT MANAGEMENT ====================
    path('clients/', views.client_list_view, name='clients'),
] 