from django.shortcuts import render
from rest_framework import viewsets, generics
from rest_framework.response import Response
from .models import Permission, Role, Organization
from .serializers import PermissionSerializer, RoleSerializer
from .permissions import IsOrgAdminOrSuperAdmin
from authentication.models import User
from django.db.models import Q
from rest_framework import serializers

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
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Role.objects.none()
            
        user = self.request.user
        
        if user.is_superuser:
            queryset = Role.objects.all()
            org_id = self.request.query_params.get('organization')
            if org_id:
                return queryset.filter(organization_id=org_id)
            return queryset

        # Org Admins see their own org roles + system-wide roles
        if hasattr(user, 'organization') and user.organization:
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
            serializer.save(organization=organization)
        else:
            # Org Admins can only create roles for their own organization.
            # Fail if they try to specify a different one.
            if 'organization' in self.request.data and self.request.data['organization'] is not None:
                raise serializers.ValidationError({
                    'organization': 'You do not have permission to create roles for other organizations.'
                })
            serializer.save(organization=user.organization)
