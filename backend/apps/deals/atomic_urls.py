"""
URL patterns for atomic financial operations
"""

from django.urls import path
from .atomic_views import (
    AtomicDealOperationsView,
    AtomicBulkOperationsView,
    AtomicCommissionOperationsView,
    OptimisticLockingView
)

urlpatterns = [
    # Atomic deal operations
    path('atomic/deals/<str:deal_id>/', AtomicDealOperationsView.as_view(), name='atomic-deal-operations'),
    
    # Atomic bulk operations
    path('atomic/bulk/', AtomicBulkOperationsView.as_view(), name='atomic-bulk-operations'),
    
    # Atomic commission operations
    path('atomic/commissions/<int:commission_id>/', AtomicCommissionOperationsView.as_view(), name='atomic-commission-operations'),
    
    # Optimistic locking operations
    path('atomic/optimistic-lock/', OptimisticLockingView.as_view(), name='optimistic-locking'),
]