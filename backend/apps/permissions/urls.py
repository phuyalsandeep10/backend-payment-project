from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.permissions.views import RoleViewSet, PermissionListView, get_salesperson_role_id

router = DefaultRouter()
router.register(r'roles', RoleViewSet, basename='role')

urlpatterns = [
    path('', include(router.urls)),
    path('all/', PermissionListView.as_view(), name='permission-list'),
    path('get-salesperson-id/', get_salesperson_role_id, name='get-salesperson-id'),
] 