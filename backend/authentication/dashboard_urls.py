from django.urls import path
from .views import DashboardStatsView, DashboardActivitiesView

urlpatterns = [
    path('stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    path('activities/', DashboardActivitiesView.as_view(), name='dashboard-activities'),
] 