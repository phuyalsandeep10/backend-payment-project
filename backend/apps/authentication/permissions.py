from rest_framework import permissions

class IsAdminOrAccountOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow admins or the owner of an account to edit it.
    Read is allowed for all authenticated users.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner of the snippet or an admin.
        return obj == request.user or request.user.is_staff 