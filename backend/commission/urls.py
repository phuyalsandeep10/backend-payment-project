from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CommissionViewSet

router = DefaultRouter()
router.register(r'', CommissionViewSet, basename='commission')

urlpatterns = [
    path('', include(router.urls)),
    path('bulk/', CommissionViewSet.as_view({'put': 'bulk_update'}), name='commission-bulk-update'),
    path('<int:pk>/calculate/', CommissionViewSet.as_view({'post': 'calculate'}), name='commission-calculate'),
    path('export/<str:format>/', CommissionViewSet.as_view({'get': 'export'}), name='commission-export'),
] 