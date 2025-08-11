from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import DealViewSet, PaymentViewSet, ActivityLogViewSet, PaymentInvoiceViewSet, PaymentApprovalViewSet, ChunkedFileUploadView

router = DefaultRouter()
router.register(r'deals', DealViewSet, basename='deal')
router.register(r'payments', PaymentViewSet, basename='payment')
router.register(r'activity-logs', ActivityLogViewSet, basename='activity-log')
router.register(r'invoices', PaymentInvoiceViewSet, basename='invoice')
router.register(r'approvals', PaymentApprovalViewSet, basename='approval')

urlpatterns = [
    path('', include(router.urls)),
    path('chunked-upload/', ChunkedFileUploadView.as_view(), name='chunked-file-upload'),
]