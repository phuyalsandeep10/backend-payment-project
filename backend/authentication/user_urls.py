from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet

# Create a router for direct /users endpoints
router = DefaultRouter()
router.register(r'', UserViewSet, basename='user')

# Direct user URLs to match frontend expectations (/api/users/)
urlpatterns = [
    path('', include(router.urls)),
] 