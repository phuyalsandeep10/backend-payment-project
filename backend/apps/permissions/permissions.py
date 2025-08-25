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
            
        # Check for organization admin role (case-insensitive and flexible)
        if request.user.role:
            role_name = request.user.role.name.strip().replace('-', ' ').lower()
            return role_name in ['organization admin', 'org admin']
        
        return False

class CanManageRoles(permissions.BasePermission):
    """
    Custom permission to only allow users with the 'can_manage_roles'
    permission to manage roles.
    """
    def has_permission(self, request, view):
        # Debug logging
        print(f"DEBUG - CanManageRoles permission check:")
        print(f"  User: {request.user}")
        print(f"  Is authenticated: {request.user.is_authenticated if request.user else False}")
        print(f"  User role: {request.user.role if request.user else None}")
        
        if request.user and request.user.is_authenticated and request.user.role:
            user_permissions = list(request.user.role.permissions.values('codename', 'name'))
            print(f"  User permissions: {user_permissions}")
            has_manage_roles = request.user.role.permissions.filter(codename='can_manage_roles').exists()
            print(f"  Has can_manage_roles: {has_manage_roles}")
        
        # Check if the user is authenticated and has a role with the required permission.
        has_permission = (
            request.user and
            request.user.is_authenticated and
            request.user.role and
            request.user.role.permissions.filter(codename='can_manage_roles').exists()
        )
        
        # Fallback: Allow Organization Admins to manage roles even without explicit permission
        if not has_permission and request.user and request.user.is_authenticated and request.user.role:
            role_name = request.user.role.name.strip().replace('-', ' ').lower()
            has_permission = role_name in ['organization admin', 'org admin']
            print(f"  Fallback check for org admin: {has_permission}")
        
        return has_permission

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
