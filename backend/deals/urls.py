from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import DealCompatViewSet, PaymentVerificationView, PaymentViewSet

# The router is the simplest way to wire up a ViewSet.
# The r'' prefix means we are registering it at the root of the included path.
router = DefaultRouter()
router.register(r'', DealCompatViewSet, basename='deal-compat')
router.register(r'payments', PaymentViewSet, basename='payment')

urlpatterns = [
    path('', include(router.urls)),
    # Payment verification endpoint
    path('payments/<str:payment_id>/verify/', PaymentVerificationView.as_view(), name='payment-verify'),
] 