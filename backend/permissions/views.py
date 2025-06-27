from django.shortcuts import render
from rest_framework import viewsets, generics
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Permission, Role
from .serializers import PermissionSerializer, RoleSerializer
from authentication.models import User
from organization.permissions import HasPermission

# Create your views here.

class PermissionListView(generics.ListAPIView):
    """
    A view to list all available permissions, grouped by category.
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [HasPermission('manage_roles')]

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
    permission_classes = [HasPermission('manage_roles')]

    def get_queryset(self):
        # Short-circuit for schema generation to avoid AnonymousUser errors
        if getattr(self, 'swagger_fake_view', False):
            return Role.objects.none()
        
        user = self.request.user
        if user.is_superuser:
            return Role.objects.all()
        
        # Crucially, only return roles for the user's organization
        return Role.objects.filter(organization=user.organization)

    def perform_create(self, serializer):
        user = self.request.user
        # Super Admins can create roles for any organization
        if user.is_superuser:
            # Organization must be provided in the request data for super admins
            organization = serializer.validated_data.get('organization')
            if not organization:
                raise serializers.ValidationError({'organization': 'This field is required for super admins.'})
            serializer.save(organization=organization)
        else:
            # Org Admins can only create roles for their own organization
            serializer.save(organization=user.organization)
