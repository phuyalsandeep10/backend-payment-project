from rest_framework import permissions
from rest_framework.permissions import BasePermission

class HasProjectPermission(BasePermission):
    """
    Custom permission to check for project-related permissions.
    """
    def has_permission(self, request, view):
        if request.user and request.user.is_superuser:
            return True

        if not request.user or not request.user.role:
            return False

        required_perms_map = {
            'list': ['view_all_projects', 'view_own_projects'],
            'create': ['create_project'],
            'retrieve': ['view_all_projects', 'view_own_projects'],
            'update': ['edit_project'],
            'partial_update': ['edit_project'],
            'destroy': ['delete_project'],
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

        if not request.user.role.permissions.filter(codename='view_all_projects').exists() and \
           request.user.role.permissions.filter(codename='view_own_projects').exists():
            return obj.created_by == request.user
            
        return True

class IsAdminOrReadOnly(BasePermission):
    """
    Legacy permission class - deprecated, use HasProjectPermission instead.
    Custom permission to only allow admin users to edit an object.
    """
    def has_permission(self, request, view):
        from rest_framework import permissions
        # Read permissions are allowed to any authenticated user,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the admin users.
        return request.user and request.user.is_staff 