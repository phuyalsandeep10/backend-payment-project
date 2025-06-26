from django.urls import path
from .views import UserListCreateView, UserDetailView, UserRegistrationView

urlpatterns = [
    path('users/', UserListCreateView.as_view(), name='user-list-create'),
    path('users/<uuid:pk>/', UserDetailView.as_view(), name='user-detail'),
    path('register/', UserRegistrationView.as_view(), name='user-register'),
]