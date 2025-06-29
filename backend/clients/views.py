from rest_framework import viewsets
from .models import Client
from .serializers import ClientSerializer
from permissions.permissions import IsOrgAdminOrSuperAdmin
from organization.models import Organization
from rest_framework import serializers

class ClientViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing Client instances.
    """
    serializer_class = ClientSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get_queryset(self):
        """
        This view should return a list of all the clients
        for the currently authenticated user's organization.
        Superusers can see all clients.
        """
        user = self.request.user
        if user.is_superuser:
            return Client.objects.all()
        
        if user.organization:
            return Client.objects.filter(organization=user.organization)
            
        return Client.objects.none()

    def perform_create(self, serializer):
        """
        Associate the client with the creator and their organization.
        Super Admins can specify an organization.
        """
        user = self.request.user
        if user.is_superuser:
            org_id = self.request.data.get('organization')
            if not org_id:
                raise serializers.ValidationError({'organization': 'This field is required for Super Admins.'})
            try:
                organization = Organization.objects.get(id=org_id)
                serializer.save(created_by=user, organization=organization)
            except Organization.DoesNotExist:
                raise serializers.ValidationError({'organization': 'Organization not found.'})
        else:
            if not user.organization:
                 raise serializers.ValidationError({'detail': 'You must belong to an organization to create clients.'})
            serializer.save(
                created_by=user,
                organization=user.organization
            )