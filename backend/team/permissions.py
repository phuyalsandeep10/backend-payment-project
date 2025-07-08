from rest_framework.permissions import BasePermission
from rest_framework import permissions

class HasTeamPermission(BasePermission):
    """
    Custom permission to check for team-related permissions.
    """
    def has_permission(self, request, view):
        if request.user and request.user.is_superuser:
            return True

        if not request.user or not request.user.role:
            return False

        required_perms_map = {
            'list': ['view_all_teams', 'view_own_teams'],
            'create': ['create_new_team'],
            'retrieve': ['view_all_teams', 'view_own_teams'],
            'update': ['edit_team_details'],
            'partial_update': ['edit_team_details'],
            'destroy': ['remove_team'],
        }
        
        required_perms = required_perms_map.get(view.action, [])
        if not required_perms:
            return False
            
        return request.user.role.permissions.filter(codename__in=required_perms).exists()

    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_superuser:
            return True

        if not request.user or not request.user.role:
            return False

        # All team members must belong to the same organization.
        if obj.organization != request.user.organization:
            return False

        # If the user can only view their own teams, check if they are the lead or a member.
        if not request.user.role.permissions.filter(codename='view_all_teams').exists() and \
           request.user.role.permissions.filter(codename='view_own_teams').exists():
            return obj.team_lead == request.user or request.user in obj.members.all()
            
        return True 