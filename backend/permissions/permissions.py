from rest_framework.permissions import BasePermission
from rest_framework import permissions

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

class CanManageRoles(permissions.BasePermission):
    """
    Custom permission to only allow users with the 'can_manage_roles'
    permission to manage roles.
    """
    def has_permission(self, request, view):
        # Check if the user is authenticated and has a role with the required permission.
        return (
            request.user and
            request.user.is_authenticated and
            request.user.role and
            request.user.role.permissions.filter(codename='can_manage_roles').exists()
        ) 