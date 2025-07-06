from django.shortcuts import render
from rest_framework import viewsets
from .models import Commission
from .serializers import CommissionSerializer
from .permissions import HasCommissionPermission
from permissions.permissions import IsOrgAdminOrSuperAdmin
from organization.models import Organization
from rest_framework import serializers

# Create your views here.

class CommissionViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing commissions.
    Now uses role-based permissions with granular access control.
    """
    serializer_class = CommissionSerializer
    permission_classes = [HasCommissionPermission]

    def get_queryset(self):
        """
        Returns commissions for the user's organization.
        Superusers can see all commissions across all organizations.
        """
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Commission.objects.none()
            
        user = self.request.user

        queryset = Commission.objects.select_related(
            'user', 'organization', 'created_by', 'updated_by'
        )

        if user.is_superuser:
            return queryset.all()
        
        if not hasattr(user, 'organization') or not user.organization:
            return Commission.objects.none()

        organization_queryset = queryset.filter(organization=user.organization)

        if hasattr(user, 'role') and user.role and user.role.permissions.filter(codename='view_all_commissions').exists():
            return organization_queryset
            
        return Commission.objects.none()

    def perform_create(self, serializer):
        """
        Set the creator of the commission record.
        """
        serializer.save(created_by=self.request.user)

    def perform_update(self, serializer):
        """
        Set the user who last updated the commission record.
        """
        serializer.save(updated_by=self.request.user)

    def get_serializer_context(self):
        """
        Pass the request to the serializer context.
        """
        return {'request': self.request}
