from django.shortcuts import render
from rest_framework import viewsets, permissions
from .models import Project
from .serializers import ProjectSerializer
from rest_framework import serializers

# Create your views here.

class ProjectViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows projects to be viewed or edited.
    Permissions are based on team membership.
    """
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        Users should only see projects associated with teams they are a member of.
        Superusers can see all projects.
        """
        # Short-circuit for schema generation
        if getattr(self, 'swagger_fake_view', False):
            return Project.objects.none()
            
        user = self.request.user
        if user.is_superuser:
            return Project.objects.all().select_related('created_by').prefetch_related('teams')
        
        # Filter projects by the teams the user is a member of.
        return Project.objects.filter(teams__members=user).distinct().select_related('created_by').prefetch_related('teams')

    def perform_create(self, serializer):
        """
        Associate the project with the creator.
        """
        serializer.save(created_by=self.request.user)

    def perform_update(self, serializer):
        """
        Set the user who last updated the project.
        """
        serializer.save(updated_by=self.request.user)

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        - Only the project creator can delete.
        - Team members can update/view.
        """
        if self.action == 'destroy':
            self.permission_classes = [permissions.IsAuthenticated, IsProjectCreator]
        elif self.action in ['update', 'partial_update', 'retrieve']:
            self.permission_classes = [permissions.IsAuthenticated, IsProjectTeamMember]
        
        return super().get_permissions()


# Custom Permissions
class IsProjectCreator(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.created_by == request.user

class IsProjectTeamMember(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return request.user in [member for team in obj.teams.all() for member in team.members.all()]
