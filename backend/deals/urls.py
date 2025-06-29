from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import DealViewSet, PaymentViewSet, ActivityLogViewSet

router = DefaultRouter()
router.register(r'deals', DealViewSet, basename='deal')
router.register(r'payments', PaymentViewSet, basename='payment')
router.register(r'activity-logs', ActivityLogViewSet, basename='activity-log')

urlpatterns = [
    path('', include(router.urls)),
]