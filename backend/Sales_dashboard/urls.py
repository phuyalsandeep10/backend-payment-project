from django.urls import path, include, re_path
from . import views

app_name = 'sales_dashboard'

urlpatterns = [
    # Top-level dashboard endpoint at /api/dashboard/
    path('', views.dashboard_view, name='dashboard'),
    # Backwards-compat: keep the old double-segment path used by frontend hook
    path('dashboard/', views.dashboard_view, name='dashboard-legacy'),
    
    # ==================== STREAK MANAGEMENT ====================
    path('streak/', views.streak_view, name='streak'),
    # New aliases to match frontend pluralised paths
    path('streaks/', views.streak_view, name='streaks'),
    path('streaks/leaderboard/', views.streak_leaderboard_view, name='streaks-leaderboard'),
    
    # ==================== PERFORMANCE TRACKING ====================
    path('standings/', views.standings_view, name='standings'),
    path('commission/', views.commission_overview_view, name='commission'),
    
    # ==================== CLIENT MANAGEMENT ====================
    path('clients/', views.client_list_view, name='clients'),
    # Additional frontend-required endpoints
    path('chart/', views.chart_view, name='chart'),
    path('goals/', views.goals_view, name='goals'),
    path('payment-verification/', views.payment_verification_view, name='payment-verification'),
] 