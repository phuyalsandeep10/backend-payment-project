from django.urls import path, include
from rest_framework_nested import routers
from .views import DealViewSet, PaymentViewSet, ActivityLogViewSet

router = routers.DefaultRouter()
router.register(r'deals', DealViewSet, basename='deal')

deals_router = routers.NestedSimpleRouter(router, r'deals', lookup='deal')
deals_router.register(r'payments', PaymentViewSet, basename='deal-payments')
deals_router.register(r'activity', ActivityLogViewSet, basename='deal-activity')

urlpatterns = [
    path('', include(router.urls)),
    path('', include(deals_router.urls)),
]