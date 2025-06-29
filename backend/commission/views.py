from django.shortcuts import render
from rest_framework import viewsets
from .models import Commission
from .serializers import CommissionSerializer
from permissions.permissions import IsOrgAdminOrSuperAdmin

# Create your views here.

class CommissionViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing commissions.
    Access is restricted to Org Admins and Super Admins.
    """
    serializer_class = CommissionSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get_queryset(self):
        """
        Returns commissions for the user's organization.
        Superusers can see all commissions across all organizations.
        """
        user = self.request.user
        if user.is_superuser:
            return Commission.objects.all()
        
        if user.organization:
            return Commission.objects.filter(organization=user.organization)
            
        return Commission.objects.none() # No org, no commissions

    def get_serializer_context(self):
        """
        Pass the request to the serializer context.
        """
        return {'request': self.request}
