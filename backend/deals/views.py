from rest_framework import viewsets
from .models import Deal, Payment, ActivityLog, logactivity
from .serializers import (
    DealSerializer, DealCreateUpdateSerializer, 
    PaymentSerializer, ActivityLogSerializer
)
from permissions.permissions import IsOrgAdminOrSuperAdmin

class DealViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Deals.
    Access is restricted to Org Admins and Super Admins.
    """
    queryset = Deal.objects.all()
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return DealCreateUpdateSerializer
        return DealSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return Deal.objects.all()
        if user.organization:
            return Deal.objects.filter(organization=user.organization)
        return Deal.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        deal = serializer.save(organization=user.organization, created_by=user)
        logactivity(deal, f"Deal created by {user.username}")

    def perform_update(self, serializer):
        user = self.request.user
        deal = serializer.save()
        logactivity(deal, f"Deal updated by {user.username}")

class PaymentViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Payments related to a specific deal.
    """
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return Payment.objects.all()
        if user.organization:
            return Payment.objects.filter(deal__organization=user.organization)
        return Payment.objects.none()

class ActivityLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    A read-only viewset for ActivityLogs related to a specific deal.
    """
    queryset = ActivityLog.objects.all()
    serializer_class = ActivityLogSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return ActivityLog.objects.all()
        if user.organization:
            return ActivityLog.objects.filter(deal__organization=user.organization)
        return ActivityLog.objects.none()