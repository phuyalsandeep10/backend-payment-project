from rest_framework.permissions import BasePermission
from authentication.models import User
from rest_framework import permissions

class IsSuperAdmin(BasePermission):
    """
    Allows access only to super administrators.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser

class IsOrganizationAdmin(BasePermission):
    """
    Allows access only to users with the 'manage_roles' permission in their organization.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.user.is_superuser:
            return True

        if not request.user.org_role:
            return False
            
        return request.user.org_role.permissions.filter(codename='manage_roles').exists()

class HasPermission(BasePermission):
    """
    Custom permission to check if a user has a specific permission codename.
    """
    def __init__(self, permission_codename):
        self.permission_codename = permission_codename
        super().__init__()

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.user.is_superuser:
            return True

        if not request.user.org_role:
            return False
            
        return request.user.org_role.permissions.filter(codename=self.permission_codename).exists() 