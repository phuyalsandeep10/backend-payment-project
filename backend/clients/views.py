from rest_framework import viewsets, serializers, permissions
from django.db.models import Count
from .models import Client
from .serializers import ClientSerializer
from .permissions import HasClientPermission
from organization.models import Organization

class ClientViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing Client instances, with granular permissions.
    """
    serializer_class = ClientSerializer
    permission_classes = [permissions.IsAuthenticated, HasClientPermission]

    def get_queryset(self):
        """
        This view should return a list of all the clients
        for the currently authenticated user's organization.
        - Superusers can see all clients.
        - Users with 'view_all_clients' can see all clients in their organization.
        - Users with 'view_own_clients' can see only clients they created.
        """
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Client.objects.none()
            
        user = self.request.user
        
        if user.is_superuser:
            return Client.objects.all()
        
        if not hasattr(user, 'organization') or not user.organization:
            return Client.objects.none()

        # Start with clients from the user's organization
        queryset = Client.objects.filter(organization=user.organization)

        # Check for role and permissions
        if hasattr(user, 'role') and user.role:
            has_view_all = user.role.permissions.filter(codename='view_all_clients').exists()
            has_view_own = user.role.permissions.filter(codename='view_own_clients').exists()

            if user.role.name == 'Salesperson':
                # Salespeople should ONLY ever see their own clients.
                # This check is explicit and overrides any other permissions.
                return queryset.filter(created_by=user)
            
            if has_view_all:
                # For other roles, if they have view_all, show all clients in the org.
                return queryset
            
            if has_view_own:
                # If they only have view_own, filter to their own clients.
                return queryset.filter(created_by=user)
        
        # Default to deny: if no relevant permissions, return nothing.
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

    def perform_update(self, serializer):
        """
        Set the user who last updated the client.
        """
        serializer.save(updated_by=self.request.user)