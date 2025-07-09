from django.shortcuts import render
from rest_framework import viewsets, generics, permissions
from rest_framework.response import Response
from .models import Permission, Role, Organization
from .serializers import PermissionSerializer, RoleSerializer
from .permissions import IsOrgAdminOrSuperAdmin, CanManageRoles
from authentication.models import User
from django.db.models import Q
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status

# Create your views here.

class PermissionListView(generics.ListAPIView):
    """
    A read-only endpoint to list all available permissions.
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # Group permissions by content_type for the UI
        grouped_data = {}
        for item in serializer.data:
            content_type = item['content_type']
            if content_type not in grouped_data:
                grouped_data[content_type] = []
            grouped_data[content_type].append(item)
            
        return Response(grouped_data)

class RoleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing Roles.
    Requires 'can_manage_roles' permission.
    """
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated, CanManageRoles]

    def get_queryset(self):
        """
        Users can only see roles within their own organization.
        """
        user = self.request.user
        if user.is_authenticated and user.organization:
            return Role.objects.filter(organization=user.organization)
        return Role.objects.none()

    def perform_create(self, serializer):
        """
        When creating a role, it must be associated with the user's organization.
        """
        serializer.save(organization=self.request.user.organization)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_salesperson_role_id(request):
    """
    Returns the ID of the 'Salesperson' role within the user's organization.
    For Super Admins, allows specifying an organization via query parameter.
    """
    user = request.user
    
    # For Super Admins, allow specifying organization or use first available
    if user.is_superuser:
        org_id = request.query_params.get('organization')
        if org_id:
            try:
                organization = Organization.objects.get(id=org_id)
            except Organization.DoesNotExist:
                return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            # Use the first available organization
            organization = Organization.objects.first()
            if not organization:
                return Response({"error": "No organizations found"}, status=status.HTTP_404_NOT_FOUND)
    else:
        # Regular users must belong to an organization
        if not user.organization:
            return Response({"error": "User does not belong to an organization"}, status=status.HTTP_400_BAD_REQUEST)
        organization = user.organization
    
    try:
        role = Role.objects.get(name="Salesperson", organization=organization)
        return Response({"id": role.id})
    except Role.DoesNotExist:
        return Response({"error": f"Salesperson role not found in organization '{organization.name}'"}, status=status.HTTP_404_NOT_FOUND)
