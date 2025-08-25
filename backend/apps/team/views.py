from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status
from .models import Team
from .serializers import TeamSerializer
from .permissions import HasTeamPermission
from apps.permissions.permissions import IsOrgAdminOrSuperAdmin
from apps.organization.models import Organization
from apps.authentication.models import User
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
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Team.objects.none()
            
        user = self.request.user

        base_queryset = Team.objects.select_related(
            'organization', 'team_lead', 'created_by', 'updated_by'
        ).prefetch_related('members', 'projects')

        if user.is_superuser:
            return base_queryset.all()

        if not hasattr(user, 'organization') or not user.organization:
            return Team.objects.none()

        organization_queryset = base_queryset.filter(organization=user.organization).order_by('-created_at', 'name')

        if hasattr(user, 'role') and user.role:
            if user.role.name.strip().replace('-', ' ').lower() in [
                'organization admin', 'org admin'
            ]:
                return organization_queryset
            if user.role.permissions.filter(codename='view_all_teams').exists():
                return organization_queryset

        if hasattr(user, 'role') and user.role and user.role.permissions.filter(codename='view_own_teams').exists():
            return organization_queryset.filter(
                models.Q(team_lead=user) | models.Q(members=user)
            ).distinct()
            
        return Team.objects.none().order_by('-created_at')

    def perform_create(self, serializer):
        """
        Associate the team with the user's organization and the creator.
        """
        user = self.request.user
        if user.is_superuser:
            org_id = serializer.validated_data.get('organization')
            if not org_id:
                raise serializers.ValidationError({'organization': 'This field is required for Super Admins.'})
            serializer.save(created_by=user, organization=org_id)
        else:
            serializer.save(created_by=user, organization=user.organization)

    def perform_update(self, serializer):
        """
        Set the user who last updated the team.
        """
        serializer.save(updated_by=self.request.user)

    @action(detail=True, methods=['post'], url_path='members')
    def add_members(self, request, pk=None):
        """Add members to team"""
        team = self.get_object()
        user_ids = request.data.get('user_ids', [])
        
        if not user_ids:
            return Response({'error': 'user_ids field is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get users from the same organization
        users = User.objects.filter(id__in=user_ids, organization=team.organization)
        
        if not users.exists():
            return Response({'error': 'No valid users found'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Add members to the team
        team.members.add(*users)
        
        # Return updated team data
        serializer = self.get_serializer(team)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['delete'], url_path='members/(?P<user_id>[^/.]+)')
    def remove_member(self, request, pk=None, user_id=None):
        """Remove member from team"""
        team = self.get_object()
        try:
            user = User.objects.get(id=user_id, organization=team.organization)
            team.members.remove(user)
            serializer = self.get_serializer(team)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
