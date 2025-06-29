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
            'create': ['create_team'],
            'retrieve': ['view_all_teams', 'view_own_teams'],
            'update': ['edit_team'],
            'partial_update': ['edit_team'],
            'destroy': ['delete_team'],
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

        if obj.organization != request.user.organization:
            return False

        # Team lead can always edit their own team
        if obj.team_lead == request.user:
            return True

        if not request.user.role.permissions.filter(codename='view_all_teams').exists() and \
           request.user.role.permissions.filter(codename='view_own_teams').exists():
            return obj.team_lead == request.user or request.user in obj.members.all()
            
        return True

class IsAdminOrTeamLeadOrReadOnly(permissions.BasePermission):
    """
    Legacy permission class - deprecated, use HasTeamPermission instead.
    Custom permission to only allow admin users or the team lead to edit an object.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user and request.user.is_staff

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.team_lead == request.user or request.user.is_staff 