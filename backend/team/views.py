from django.shortcuts import render
from rest_framework import viewsets
from .models import Team
from .serializers import TeamSerializer
from permissions.permissions import IsOrgAdminOrSuperAdmin

# Create your views here.

class TeamViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Team instances.
    Access is restricted to Org Admins and Super Admins.
    """
    serializer_class = TeamSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get_queryset(self):
        """
        This view should return a list of all the teams
        for the currently authenticated user's organization.
        Superusers can see all teams.
        """
        user = self.request.user
        if user.is_superuser:
            return Team.objects.all()

        if user.organization:
            return Team.objects.filter(organization=user.organization)

        return Team.objects.none()

    def perform_create(self, serializer):
        """
        Associate the team with the user's organization.
        """
        serializer.save(organization=self.request.user.organization)
