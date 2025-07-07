from rest_framework.permissions import BasePermission, SAFE_METHODS

class CanAccessClient(BasePermission):
    """
    Custom permission to only allow users with specific permissions to access client data.
    - SuperAdmin and OrgAdmin have full access.
    - Salespersons can view clients assigned to them or within their team.
    - All other roles are denied.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        if user.is_superuser or (user.role and user.role.name.replace(' ', '').lower() in ['orgadmin', 'admin']):
            return True
        
        # Allow Salespersons to manage (create/read) clients. Object-level checks will validate write access.
        if user.role and user.role.name.replace(' ', '').lower() == 'salesperson':
            return True  # Object permissions will restrict access as needed

        return False

    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        if user.is_superuser or (user.role and user.role.name.replace(' ', '').lower() in ['orgadmin', 'admin'] and obj.organization == user.organization):
            return True

        # Salespersons can view or manage clients assigned to them or in their team
        if user.role and user.role.name.replace(' ', '').lower() == 'salesperson':
            is_assigned = getattr(obj, 'salesperson', None) == user
            is_in_team = hasattr(obj, 'teams') and any(team in user.teams.all() for team in obj.teams.all())

            if is_assigned or is_in_team:
                return True

        return False 