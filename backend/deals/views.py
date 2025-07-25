from rest_framework import viewsets, status, filters
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from .models import Deal, Payment, ActivityLog, PaymentInvoice, PaymentApproval
from .serializers import (
    DealSerializer, SalespersonDealSerializer, PaymentSerializer, ActivityLogSerializer, DealExpandedViewSerializer,
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
    permission_classes = [HasPermission]
    lookup_field = 'deal_id'
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['client', 'payment_status', 'verification_status', 'source_type', 'payment_method']
    search_fields = ['deal_id', 'deal_name', 'client__client_name']
    ordering_fields = ['deal_date', 'due_date', 'deal_value', 'created_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        """
        Use SalespersonDealSerializer for salesperson users to include payments_read field.
        """
        user = self.request.user
        if hasattr(user, 'role') and user.role:
            role_name = user.role.name.strip().replace('-', ' ').lower()
            if 'salesperson' in role_name or 'sales' in role_name:
                return SalespersonDealSerializer
        return DealSerializer

    def get_queryset(self):
        """Optimize queries with select_related and prefetch_related"""
        return Deal.objects.select_related(
            'client',
            'created_by',
            'created_by__organization'
        ).prefetch_related(
            'payments'
        ).filter(
            organization=self.request.user.organization
        )

    def list(self, request, *args, **kwargs):
        """Optimized list view with pagination"""
        queryset = self.get_queryset()
        
        # Add filtering
        status = request.query_params.get('status')
        if status:
            queryset = queryset.filter(payment_status=status)
        
        # Add search
        search = request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(deal_name__icontains=search) |
                Q(client__client_name__icontains=search) |
                Q(deal_id__icontains=search)
            )
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

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
        serializer = DealExpandedViewSerializer(deal)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='log-activity', serializer_class=ActivityLogSerializer)
    def log_activity(self, request, deal_id=None):
        """
        Returns the activity log for a specific deal.
        """
        deal = self.get_object()
        activities = deal.activity_logs.all().order_by('-timestamp')
        serializer = self.get_serializer(activities, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='invoices')
    def list_invoices(self, request, deal_id=None):
        deal = self.get_object()
        invoices = PaymentInvoice.objects.filter(deal=deal)
        serializer = PaymentInvoiceSerializer(invoices, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='payments')
    def list_payments(self, request, deal_id=None):
        """
        Get all payments for this deal with their related invoices and approvals.
        """
        deal = self.get_object()
        payments = Payment.objects.filter(deal=deal).select_related(
            'deal', 'deal__client', 'deal__organization'
        ).prefetch_related(
            'invoice', 'approvals', 'approvals__approved_by'
        ).order_by('-payment_date')
        
        from .serializers import PaymentExpandedSerializer
        serializer = PaymentExpandedSerializer(payments, many=True)
        
        return Response({
            'deal': {
                'deal_id': deal.deal_id,
                'deal_name': deal.deal_name,
                'deal_value': deal.deal_value,
                'client_name': deal.client.client_name if deal.client else None,
            },
            'payments': serializer.data,
            'total_payments': payments.count(),
            'total_amount': sum(payment.received_amount for payment in payments)
        })

class PaymentViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Payments with support for filtering by deal ID.
    """
    serializer_class = PaymentSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        # Prevent crash during schema generation
        if getattr(self, 'swagger_fake_view', False):
            return Payment.objects.none()
        
        user = self.request.user
        queryset = Payment.objects.select_related('deal', 'deal__organization', 'deal__client')
        
        # Filter by organization
        if user.is_superuser:
            pass  # Superuser can see all payments
        elif user.organization:
            queryset = queryset.filter(deal__organization=user.organization)
        else:
            return Payment.objects.none()
        
        # Filter by deal ID if provided in query params
        deal_id = self.request.query_params.get('deal_id', None)
        if deal_id:
            queryset = queryset.filter(deal__deal_id=deal_id)
        
        # Filter by deal UUID if provided in query params
        deal_uuid = self.request.query_params.get('deal', None)
        if deal_uuid:
            queryset = queryset.filter(deal_id=deal_uuid)
        
        return queryset

    def perform_create(self, serializer):
        serializer.save()

    @action(detail=False, methods=['get'], url_path='by-deal/(?P<deal_id>[^/.]+)')
    def by_deal(self, request, deal_id=None):
        """
        Get all payments for a specific deal with their related invoices and approvals.
        """
        try:
            # Find the deal by deal_id
            deal = get_object_or_404(Deal, deal_id=deal_id, organization=request.user.organization)
            
            # Get all payments for this deal with related data
            payments = Payment.objects.filter(deal=deal).select_related(
                'deal', 'deal__client', 'deal__organization'
            ).prefetch_related(
                'invoice', 'approvals', 'approvals__approved_by'
            ).order_by('-payment_date')
            
            # Serialize with expanded data
            from .serializers import PaymentExpandedSerializer
            serializer = PaymentExpandedSerializer(payments, many=True)
            
            return Response({
                'deal': {
                    'deal_id': deal.deal_id,
                    'deal_name': deal.deal_name,
                    'deal_value': deal.deal_value,
                    'client_name': deal.client.client_name if deal.client else None,
                },
                'payments': serializer.data,
                'total_payments': payments.count(),
                'total_amount': sum(payment.received_amount for payment in payments)
            })
            
        except Deal.DoesNotExist:
            return Response(
                {'error': f'Deal with ID {deal_id} not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': f'Error retrieving payments: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

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
    lookup_field = 'invoice_id'  # Use invoice_id instead of id

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
