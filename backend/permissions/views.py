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
from django.db import IntegrityError

# Create your views here.

class PermissionListView(generics.ListAPIView):
    """
    List all available permissions.  
    Accessible to superusers **or** any user whose role has the `can_manage_roles` permission (i.e., Org-Admins).
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

    # Any authenticated user can read the list (harmless metadata)
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
        user = self.request.user
        if user.is_superuser:
            # Super admins can create roles for any organization or system-wide
            # The organization ID can be passed in the request data
            org_id = self.request.data.get('organization')
            organization = None
            if org_id:
                try:
                    organization = Organization.objects.get(id=org_id)
                except Organization.DoesNotExist:
                    raise serializers.ValidationError({'organization': 'Organization not found.'})
            
            # Handle potential duplicate role creation
            try:
                serializer.save(organization=organization)
            except IntegrityError:
                # If role already exists, fetch and return the existing one
                role_name = serializer.validated_data.get('name')
                existing_role = Role.objects.get(name=role_name, organization=organization)
                # Update the serializer instance to return the existing role
                serializer.instance = existing_role
                
        else:
            # Org Admins can only create roles for their own organization.
            # Fail if they try to specify a different one.
            if 'organization' in self.request.data and self.request.data['organization'] is not None:
                raise serializers.ValidationError({
                    'organization': 'You do not have permission to create roles for other organizations.'
                })
            
            # Handle potential duplicate role creation
            try:
                serializer.save(organization=user.organization)
            except IntegrityError:
                # If role already exists, fetch and return the existing one
                role_name = serializer.validated_data.get('name')
                existing_role = Role.objects.get(name=role_name, organization=user.organization)
                # Update the serializer instance to return the existing role
                serializer.instance = existing_role

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
