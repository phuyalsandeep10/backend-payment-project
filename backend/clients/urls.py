from django.urls import path
from .views import ClientDetailView,ClientListCreateView

urlpatterns = [
    path("clients/",ClientListCreateView.as_view(),name="client-list-create"),
    path("clients/<int:pk>/",ClientDetailView.as_view(),name="client-detail"),
]
