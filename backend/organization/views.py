from django.shortcuts import render
from rest_framework import viewsets, generics, status
from rest_framework.response import Response
from .models import Organization
from authentication.models import User
from .serializers import OrganizationSerializer, OrganizationDetailSerializer, OrganizationRegistrationSerializer
from .permissions import IsSuperAdmin, HasPermission
from authentication.serializers import UserSerializer

# Create your views here.

class OrganizationViewSet(viewsets.ModelViewSet):
    """
    This viewset automatically provides `list`, `create`, `retrieve`,
    `update` and `destroy` actions.
    """
    queryset = Organization.objects.all()
    permission_classes = [IsSuperAdmin]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return OrganizationDetailSerializer
        return OrganizationSerializer

class OrgAdminViewSet(viewsets.ReadOnlyModelViewSet):
    """
    A viewset for listing organization admins. An admin is defined as a user
    who has a role with 'manage_roles' permission.
    """
    serializer_class = UserSerializer
    permission_classes = [HasPermission('view_user')]

    def get_queryset(self):
        """
        This view should return a list of all users in the user's organization
        who have the 'manage_roles' permission.
        """
        # Short-circuit for schema generation to avoid AnonymousUser errors
        if getattr(self, 'swagger_fake_view', False):
            return User.objects.none()

        user = self.request.user
        if user.is_superuser:
            # Superusers see all organization admins across all orgs
            return User.objects.filter(org_role__permissions__codename='manage_roles')
        
        if user.organization:
            # Org users see admins within their own organization
            return User.objects.filter(
                organization=user.organization,
                org_role__permissions__codename='manage_roles'
            )
        
        return User.objects.none()

class OrganizationRegistrationView(generics.CreateAPIView):
    """
    A view for registering a new organization and its first admin.
    """
    serializer_class = OrganizationRegistrationSerializer
    permission_classes = [IsSuperAdmin]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        organization = serializer.save()
        # Return the created organization's data
        response_serializer = OrganizationSerializer(organization)
        headers = self.get_success_headers(response_serializer.data)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED, headers=headers)
