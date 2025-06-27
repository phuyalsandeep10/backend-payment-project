from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PermissionListView, RoleViewSet

router = DefaultRouter()
router.register(r'roles', RoleViewSet, basename='role')

urlpatterns = [
    path('', include(router.urls)),
    path('all/', PermissionListView.as_view(), name='permission-list'),
] 