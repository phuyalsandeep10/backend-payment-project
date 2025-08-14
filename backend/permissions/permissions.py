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
            
        return request.user.role and request.user.role.name == 'Organization Admin'

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

class CanManageUserPasswords(BasePermission):
    """
    Custom permission to only allow Organization Admins and Super Admins to manage user passwords.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Superusers can manage any passwords
        if request.user.is_superuser:
            return True
        
        # Organization Admins can manage passwords in their organization
        return request.user.role and request.user.role.name == 'Organization Admin'
    
    def has_object_permission(self, request, view, obj):
        """
        Check if the user can manage the specific target user's password
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Superusers can manage any passwords
        if request.user.is_superuser:
            return True
        
        # Organization Admins can only manage passwords within their organization
        if request.user.role and request.user.role.name == 'Organization Admin':
            return (
                request.user.organization and 
                request.user.organization == obj.organization
            )
        
        return False
