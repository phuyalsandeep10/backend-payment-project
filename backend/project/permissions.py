from rest_framework import permissions

class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow admin users to edit an object.
    """
    def has_permission(self, request, view):
        # Read permissions are allowed to any authenticated user,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the admin users.
        return request.user and request.user.is_staff 