from rest_framework import viewsets, status
from django.shortcuts import get_object_or_404
from .models import Deal, Payment, ActivityLog, PaymentInvoice, PaymentApproval
from .serializers import (
    DealSerializer, PaymentSerializer, ActivityLogSerializer, DealExpandedViewSerializer,
    PaymentInvoiceSerializer, PaymentApprovalSerializer
)
from .permissions import HasPermission
from rest_framework.response import Response
from rest_framework.decorators import action

class DealViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Deals, with granular permission checks and optimized queries.
    """
    serializer_class = DealSerializer
    # permission_classes = [HasPermission] # Temporarily disabled for testing
    lookup_field = 'deal_id'

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Deal.objects.none()

        user = self.request.user
        queryset = Deal.objects.select_related(
            'organization', 'client', 'created_by', 'updated_by'
        ).prefetch_related(
            'payments', 'activity_logs'
        )

        if user.is_superuser:
            return queryset.all()

        if not user.organization:
            return Deal.objects.none()

        org_queryset = queryset.filter(organization=user.organization)

        if user.role and user.role.permissions.filter(codename='view_all_deals').exists():
            return org_queryset
        
        return org_queryset.filter(created_by=user)

    def perform_create(self, serializer):
        serializer.save(
            organization=self.request.user.organization,
            created_by=self.request.user,
            updated_by=self.request.user
        )

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    @action(detail=True, methods=['get'], url_path='expand', serializer_class=DealExpandedViewSerializer)
    def expand(self, request, deal_id=None):
        """
        Provides an expanded view of a single deal, including detailed
        verification information and a full payment history.
        """
        deal = self.get_object()
        serializer = self.get_serializer(deal)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='invoices')
    def list_invoices(self, request, deal_id=None):
        deal = self.get_object()
        invoices = PaymentInvoice.objects.filter(deal=deal)
        serializer = PaymentInvoiceSerializer(invoices, many=True)
        return Response(serializer.data)

class PaymentViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Payments for a specific Deal.
    """
    serializer_class = PaymentSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        deal_pk = self.kwargs.get('deal_pk')
        if deal_pk:
            return Payment.objects.select_related('deal').filter(deal_id=deal_pk)
        return Payment.objects.none()

    def perform_create(self, serializer):
        deal = get_object_or_404(Deal, pk=self.kwargs.get('deal_pk'))
        serializer.save(deal=deal)

class ActivityLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    A read-only viewset for ActivityLogs related to a specific deal.
    """
    serializer_class = ActivityLogSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return ActivityLog.objects.none()
            
        deal_pk = self.kwargs.get('deal_pk')
        deal = get_object_or_404(Deal, pk=deal_pk)
        
        # The permission class already ensures the user can view the deal.
        return ActivityLog.objects.filter(deal=deal).order_by('-timestamp')

class PaymentInvoiceViewSet(viewsets.ModelViewSet):
    queryset = PaymentInvoice.objects.all()
    serializer_class = PaymentInvoiceSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        # Prevent crash during schema generation
        if getattr(self, 'swagger_fake_view', False):
            return PaymentInvoice.objects.none()
        
        # Filter by the organization of the logged-in user
        if self.request.user.is_authenticated and hasattr(self.request.user, 'organization'):
            return PaymentInvoice.objects.filter(deal__organization=self.request.user.organization)
        
        return PaymentInvoice.objects.none()

class PaymentApprovalViewSet(viewsets.ModelViewSet):
    queryset = PaymentApproval.objects.all()
    serializer_class = PaymentApprovalSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        # Prevent crash during schema generation
        if getattr(self, 'swagger_fake_view', False):
            return PaymentApproval.objects.none()
        
        # Filter by the organization of the logged-in user
        if self.request.user.is_authenticated and hasattr(self.request.user, 'organization'):
            return PaymentApproval.objects.filter(deal__organization=self.request.user.organization)
        
        return PaymentApproval.objects.none()