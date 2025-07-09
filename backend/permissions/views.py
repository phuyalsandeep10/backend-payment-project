from django.shortcuts import render
from rest_framework import viewsets, generics
from rest_framework.response import Response
from .models import Permission, Role, Organization
from .serializers import PermissionSerializer, RoleSerializer
from .permissions import IsOrgAdminOrSuperAdmin
from authentication.models import User
from django.db.models import Q
from rest_framework import serializers
from django.db import IntegrityError

# Create your views here.

class PermissionListView(generics.ListAPIView):
    """
    A view to list all available permissions, grouped by category.
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # Group permissions by category for the UI
        grouped_data = {}
        for item in serializer.data:
            category = item['category']
            if category not in grouped_data:
                grouped_data[category] = []
            grouped_data[category].append(item)
            
        return Response(grouped_data)

class RoleViewSet(viewsets.ModelViewSet):
    """
    A viewset for an Org Admin to manage roles within their own organization.
    """
    serializer_class = RoleSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return Role.objects.all()
        
        # Org Admins should be able to see their own roles and system-wide roles
        if user.organization:
            return Role.objects.filter(Q(organization=user.organization) | Q(organization__isnull=True))
            
        return Role.objects.none() # Should not happen for an Org Admin

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
