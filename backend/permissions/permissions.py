from rest_framework.permissions import BasePermission

class IsOrgAdminOrSuperAdmin(BasePermission):
    """
    Allows access only to Super Admins or users with the 'Org Admin' role.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
            
        if request.user.is_superuser:
            return True
            
        return request.user.role and request.user.role.name == 'Org Admin' 