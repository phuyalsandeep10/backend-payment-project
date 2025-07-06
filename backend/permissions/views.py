from django.shortcuts import render
from rest_framework import viewsets, generics, permissions
from rest_framework.response import Response
from .models import Permission, Role, Organization
from .serializers import PermissionSerializer, RoleSerializer
from .permissions import IsOrgAdminOrSuperAdmin, CanManageRoles
from authentication.models import User
from django.db.models import Q
from rest_framework import serializers

# Create your views here.

class PermissionListView(generics.ListAPIView):
    """
    A read-only endpoint to list all available permissions.
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [permissions.IsAdminUser]

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
