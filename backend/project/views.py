from django.shortcuts import render
from rest_framework import viewsets
from .models import Project
from .serializers import ProjectSerializer
from .permissions import HasProjectPermission
from organization.models import Organization
from rest_framework import serializers

# Create your views here.

class ProjectViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows projects to be viewed or edited.
    Now uses role-based permissions.
    """
    serializer_class = ProjectSerializer
    permission_classes = [HasProjectPermission]

    def get_queryset(self):
        """
        This view should return a list of all the projects
        for the currently authenticated user's organization.
        Superusers can see all projects.
        """
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Project.objects.none()
            
        user = self.request.user
        if user.is_superuser:
            return Project.objects.all()
        
        if not hasattr(user, 'organization') or not user.organization:
            return Project.objects.none()

        if hasattr(user, 'role') and user.role and user.role.permissions.filter(codename='view_all_projects').exists():
            return Project.objects.filter(organization=user.organization)

        if hasattr(user, 'role') and user.role and user.role.permissions.filter(codename='view_own_projects').exists():
            return Project.objects.filter(organization=user.organization, created_by=user)
            
        return Project.objects.none()
    
    def perform_create(self, serializer):
        """
        Associate the project with the user's organization.
        Super Admins can specify an organization.
        """
        user = self.request.user
        if user.is_superuser:
            org_id = self.request.data.get('organization')
            if org_id:
                try:
                    organization = Organization.objects.get(id=org_id)
                    serializer.save(organization=organization, created_by=user)
                except Organization.DoesNotExist:
                    raise serializers.ValidationError({'organization': 'Organization not found.'})
            else:
                serializer.save(created_by=user)
        else:
            serializer.save(organization=user.organization, created_by=user)
