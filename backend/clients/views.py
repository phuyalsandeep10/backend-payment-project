from rest_framework import viewsets, serializers
from .models import Client
from .serializers import ClientSerializer
from .permissions import HasClientPermission
from organization.models import Organization

class ClientViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing Client instances, with granular permissions.
    """
    serializer_class = ClientSerializer
    permission_classes = [HasClientPermission]

    def get_queryset(self):
        """
        This view should return a list of all the clients
        for the currently authenticated user's organization.
        Superusers can see all clients.
        """
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Client.objects.none()
            
        user = self.request.user
        if user.is_superuser:
            return Client.objects.all()
        
        if not hasattr(user, 'organization') or not user.organization:
            return Client.objects.none()

        if hasattr(user, 'role') and user.role and user.role.permissions.filter(codename='view_all_clients').exists():
            return Client.objects.filter(organization=user.organization)

        if hasattr(user, 'role') and user.role and user.role.permissions.filter(codename='view_own_clients').exists():
            return Client.objects.filter(organization=user.organization, created_by=user)
            
        return Client.objects.none()

    def perform_create(self, serializer):
        """
        Associate the client with the creator and their organization.
        Super Admins can optionally specify an organization or use a default one.
        """
        user = self.request.user
        if user.is_superuser:
            org_id = self.request.data.get('organization')
            organization = None
            
            if org_id:
                try:
                    organization = Organization.objects.get(id=org_id)
                except Organization.DoesNotExist:
                    raise serializers.ValidationError({'organization': 'Organization not found.'})
            else:
                # For SuperAdmins without specified organization, use the first available organization
                # or create a default system organization
                organization = Organization.objects.first()
                if not organization:
                    # Create a default system organization for SuperAdmin operations
                    organization = Organization.objects.create(
                        name="System Organization",
                        description="Default organization for system operations"
                    )
            
            serializer.save(created_by=user, organization=organization)
        else:
            if not user.organization:
                raise serializers.ValidationError({'detail': 'You must belong to an organization to create clients.'})
            serializer.save(
                created_by=user,
                organization=user.organization
            )