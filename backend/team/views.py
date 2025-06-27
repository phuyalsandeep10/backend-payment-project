from django.shortcuts import render
from rest_framework import viewsets
from .models import Team
from .serializers import TeamSerializer
from .permissions import IsAdminOrTeamLeadOrReadOnly
from organization.permissions import IsOrganizationAdmin

# Create your views here.

class TeamViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows teams to be viewed or edited.
    """
    serializer_class = TeamSerializer

    def get_queryset(self):
        """
        This view should return a list of all the teams
        for the currently authenticated user's organization.
        """
        # Short-circuit for schema generation to avoid AnonymousUser errors
        if getattr(self, 'swagger_fake_view', False):
            return Team.objects.none()

        user = self.request.user
        if user.is_staff or (user.org_role and user.org_role.name == 'SUPER_ADMIN'):
            return Team.objects.all()
        return Team.objects.filter(organization=user.organization)

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.action == 'create':
            self.permission_classes = [IsOrganizationAdmin]
        else:
            self.permission_classes = [IsAdminOrTeamLeadOrReadOnly]
        return super(self.__class__, self).get_permissions()

    def perform_create(self, serializer):
        """
        Add the creating user to the team's members and set the organization.
        """
        team = serializer.save(organization=self.request.user.organization)
        team.members.add(self.request.user)
