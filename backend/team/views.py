from django.shortcuts import render
from rest_framework import viewsets
from .models import Team
from .serializers import TeamSerializer
from .permissions import HasTeamPermission
from permissions.permissions import IsOrgAdminOrSuperAdmin
from organization.models import Organization
from rest_framework import serializers
from django.db import models

# Create your views here.

class TeamViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Team instances.
    Now uses role-based permissions with granular access control.
    """
    serializer_class = TeamSerializer
    permission_classes = [HasTeamPermission]

    def get_queryset(self):
        """
        This view should return a list of all the teams
        for the currently authenticated user's organization.
        Superusers can see all teams.
        """
        user = self.request.user
        if user.is_superuser:
            return Team.objects.all()

        if not user.organization:
            return Team.objects.none()

        if user.role and user.role.permissions.filter(codename='view_all_teams').exists():
            return Team.objects.filter(organization=user.organization)

        if user.role and user.role.permissions.filter(codename='view_own_teams').exists():
            # Show teams where user is team lead or member
            return Team.objects.filter(
                organization=user.organization
            ).filter(
                models.Q(team_lead=user) | models.Q(members=user)
            ).distinct()
            
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
