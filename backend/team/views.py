from django.shortcuts import render
from rest_framework import viewsets
from .models import Team
from .serializers import TeamSerializer
from permissions.permissions import IsOrgAdminOrSuperAdmin
from organization.models import Organization
from rest_framework import serializers

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
        Super Admins can specify an organization.
        """
        user = self.request.user
        if user.is_superuser:
            org_id = self.request.data.get('organization')
            if not org_id:
                raise serializers.ValidationError({'organization': 'This field is required for Super Admins.'})
            try:
                organization = Organization.objects.get(id=org_id)
                serializer.save(organization=organization)
            except Organization.DoesNotExist:
                raise serializers.ValidationError({'organization': 'Organization not found.'})
        else:
            serializer.save(organization=user.organization)
