from django.urls import path
from .views import DashboardView, DailyStandingsView, CommissionOverviewView, SalespersonClientListView

urlpatterns = [
    path('', DashboardView.as_view(), name='dashboard'),
    path('standings/', DailyStandingsView.as_view(), name='daily-standings'),
    path('commission-overview/', CommissionOverviewView.as_view(), name='commission-overview'),
    path('client-list/', SalespersonClientListView.as_view(), name='client-list'),
] 