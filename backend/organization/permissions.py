from rest_framework import permissions

class IsOrganizationMember(permissions.BasePermission):
    """
    Allows access only to users who are members of the organization.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any user who is part of the organization.
        if request.method in permissions.SAFE_METHODS:
            return request.user.organization == obj
        # Write permissions are only allowed to admins.
        return request.user.is_staff 