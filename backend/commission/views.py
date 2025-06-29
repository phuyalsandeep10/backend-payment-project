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
        user = self.request.user
        if user.is_superuser:
            return Commission.objects.all()
        
        if not user.organization:
            return Commission.objects.none()

        if user.role and user.role.permissions.filter(codename='view_all_commissions').exists():
            return Commission.objects.filter(organization=user.organization)
            
        return Commission.objects.none()

    def perform_create(self, serializer):
        """
        Associate the commission with the user's organization.
        Super Admins can specify an organization.
        """
        user = self.request.user
        if user.is_superuser:
            org_id = self.request.data.get('organization')
            if org_id:
                try:
                    organization = Organization.objects.get(id=org_id)
                    serializer.save(organization=organization)
                except Organization.DoesNotExist:
                    raise serializers.ValidationError({'organization': 'Organization not found.'})
            else:
                serializer.save()
        else:
            serializer.save(organization=user.organization)

    def get_serializer_context(self):
        """
        Pass the request to the serializer context.
        """
        return {'request': self.request}
