from rest_framework.permissions import BasePermission
from rest_framework import permissions

class IsOrgAdminOrSuperAdmin(BasePermission):
    """
    Custom permission to only allow access to organization admins or super admins.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Superusers have access everywhere
        if request.user.is_superuser:
            return True
            
        # Normalize role name to handle case, spaces, and hyphens variations
        def _norm(name: str) -> str:
            return name.lower().replace(' ', '').replace('-', '') if name else ''

        return request.user.role and _norm(request.user.role.name) in [
            'orgadmin', 'admin', 'organizationadmin', 'superadmin'
        ]

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

class IsSuperAdmin(BasePermission):
    """
    Custom permission to only allow access to super admins.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser 
