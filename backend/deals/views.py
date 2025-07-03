from rest_framework import viewsets
from .models import Deal, Payment, ActivityLog, logactivity
from .serializers import (
    DealSerializer, DealCreateUpdateSerializer, 
    PaymentSerializer, ActivityLogSerializer
)
from .permissions import HasPermission
from django.shortcuts import render
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status

class DealViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Deals, with granular permission checks.
    """
    serializer_class = DealSerializer
    permission_classes = [HasPermission]

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return DealCreateUpdateSerializer
        return DealSerializer

    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Deal.objects.none()
            
        user = self.request.user
        if user.is_superuser:
            return Deal.objects.all()
        
        # Should not happen due to permission check, but as a safeguard
        if not hasattr(user, 'organization') or not user.organization:
            return Deal.objects.none()

        # Users with 'view_all_deals' can see all deals in their org
        if hasattr(user, 'role') and user.role and user.role.permissions.filter(codename='view_all_deals').exists():
            return Deal.objects.filter(organization=user.organization)
        
        # Users with 'view_own_deals' can only see deals they created
        if hasattr(user, 'role') and user.role and user.role.permissions.filter(codename='view_own_deals').exists():
            return Deal.objects.filter(organization=user.organization, created_by=user)
        
        return Deal.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        deal = serializer.save(organization=user.organization, created_by=user)
        logactivity(deal, f"Deal created by {user.username}")

    def perform_update(self, serializer):
        user = self.request.user
        deal = serializer.save()
        logactivity(deal, f"Deal updated by {user.username}")

    @action(detail=True, methods=['post'])
    def log_activity(self, request, pk=None, client_pk=None):
        deal = self.get_object()
        message = request.data.get('message')
        if not message:
            return Response({'error': 'Message is required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        full_message = f"{message} (by {request.user.username})"
        logactivity(deal, full_message)
        return Response({'status': 'activity logged'}, status=status.HTTP_201_CREATED)

    def create(self, request, *args, **kwargs):
        # Use the create serializer for validation
        serializer = DealCreateUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        
        # Use the full serializer for the response to include all fields like 'id'
        deal = serializer.instance
        response_serializer = DealSerializer(deal)
        headers = self.get_success_headers(response_serializer.data)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED, headers=headers)

class PaymentViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Payments for a specific Deal.
    Permissions are inherited from the parent Deal.
    """
    serializer_class = PaymentSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        # Handle three-level nesting: clients/{client_pk}/deals/{deal_pk}/payments/
        deal_pk = self.kwargs.get('deal_pk')
        if deal_pk:
            return Payment.objects.filter(deal_id=deal_pk)
        return Payment.objects.none()

    def perform_create(self, serializer):
        # Associate the payment with the correct deal from the URL
        deal_pk = self.kwargs.get('deal_pk')
        if not deal_pk:
            # Fallback: try other possible parameter names
            deal_pk = self.kwargs.get('pk')
        
        if deal_pk:
            deal = Deal.objects.get(pk=deal_pk)
            serializer.save(deal=deal)
        else:
            # This should not happen if URLs are configured correctly
            raise ValueError("Could not determine deal_pk from URL parameters")

class ActivityLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    A read-only viewset for ActivityLogs related to a specific deal.
    """
    serializer_class = ActivityLogSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return ActivityLog.objects.none()
            
        # Handle three-level nesting: clients/{client_pk}/deals/{deal_pk}/activity/
        deal_pk = self.kwargs.get('deal_pk')
        user = self.request.user
        if user.is_superuser:
            return ActivityLog.objects.filter(deal_id=deal_pk)
        if hasattr(user, 'organization') and user.organization:
            return ActivityLog.objects.filter(deal_id=deal_pk, deal__organization=user.organization)
        return ActivityLog.objects.none()