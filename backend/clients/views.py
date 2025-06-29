from rest_framework import viewsets
from .models import Client
from .serializers import ClientSerializer
from permissions.permissions import IsOrgAdminOrSuperAdmin

class ClientViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing Client instances.
    """
    serializer_class = ClientSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get_queryset(self):
        """
        This view should return a list of all the clients
        created by the currently authenticated user.
        Superusers can see all clients.
        """
        user = self.request.user
        if user.is_superuser:
            return Client.objects.all()
        return Client.objects.filter(created_by=user)

    def perform_create(self, serializer):
        """
        Associate the client with the creator and their organization.
        """
        serializer.save(
            created_by=self.request.user,
            organization=self.request.user.organization
        )