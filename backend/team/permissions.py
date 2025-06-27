from rest_framework import permissions

class IsAdminOrTeamLeadOrReadOnly(permissions.BasePermission):
    """
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