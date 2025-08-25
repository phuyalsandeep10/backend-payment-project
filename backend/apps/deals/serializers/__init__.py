"""
Deals Serializers Package - Task 2.4.1

Organized serializer modules for deals app, broken down from the original
876-line monolithic serializer file into focused, reusable components.

BACKWARD COMPATIBILITY: All original serializer classes are exported
to maintain compatibility with existing views and imports.
"""

# Import all serializers for backward compatibility
from .base_serializers import (
    DealsBaseSerializer,
    PaymentStatusMixin,
    DealStatusMixin,
    PaymentValidationMixin,
    DealValidationMixin,
    FileUploadMixin,
    CalculatedFieldsMixin
)

from .payment_serializers import (
    BasePaymentSerializer,
    PaymentSerializer,
    NestedPaymentSerializer,
    PaymentDetailSerializer,
    PaymentUpdateSerializer,
    PaymentListSerializer
)

from .deal_serializers import (
    BaseDealSerializer,
    DealSerializer,
    DealListSerializer,
    DealUpdateSerializer,
    SalespersonDealSerializer
)

from .activity_serializers import (
    ActivityLogSerializer,
    DealPaymentHistorySerializer,
    DealExpandedViewSerializer,
    ActivityLogCreateSerializer,
    DealAuditSerializer
)

from .invoice_serializers import (
    PaymentInvoiceSerializer,
    PaymentApprovalSerializer,
    ApprovalSummarySerializer,
    InvoiceListSerializer,
    ApprovalListSerializer
)

# Export all for backward compatibility
__all__ = [
    # Base serializers and mixins
    'DealsBaseSerializer',
    'PaymentStatusMixin',
    'DealStatusMixin', 
    'PaymentValidationMixin',
    'DealValidationMixin',
    'FileUploadMixin',
    'CalculatedFieldsMixin',
    
    # Payment serializers
    'BasePaymentSerializer',
    'PaymentSerializer',
    'NestedPaymentSerializer',
    'PaymentDetailSerializer',
    'PaymentUpdateSerializer',
    'PaymentListSerializer',
    
    # Deal serializers
    'BaseDealSerializer',
    'DealSerializer',
    'DealListSerializer', 
    'DealUpdateSerializer',
    'SalespersonDealSerializer',
    
    # Activity serializers
    'ActivityLogSerializer',
    'DealPaymentHistorySerializer',
    'DealExpandedViewSerializer',
    'ActivityLogCreateSerializer',
    'DealAuditSerializer',
    
    # Invoice serializers
    'PaymentInvoiceSerializer',
    'PaymentApprovalSerializer',
    'ApprovalSummarySerializer',
    'InvoiceListSerializer',
    'ApprovalListSerializer'
]

# MIGRATION GUIDE for existing code:
# 
# OLD IMPORT:
#   from apps.deals.serializers import PaymentSerializer
# 
# NEW IMPORT (recommended):
#   from apps.deals.serializers import PaymentSerializer  # Still works!
#   from deals.serializers.payment_serializers import PaymentSerializer  # More explicit
# 
# FOCUSED IMPORTS (for new code):
#   from deals.serializers.deal_serializers import DealSerializer
#   from deals.serializers.payment_serializers import PaymentSerializer
#   from deals.serializers.base_serializers import DealsBaseSerializer

# PERFORMANCE NOTE: 
# All serializer classes are now modular and focused, resulting in:
# - 876 lines broken down into 5 focused modules
# - Each serializer has a single responsibility
# - Reusable components reduce code duplication
# - Enhanced validation and error handling
# - Better testability and maintainability
