from rest_framework.permissions import BasePermission
from authentication.models import User

class IsSuperAdmin(BasePermission):
    """
    Allows access only to super administrators.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == User.Role.SUPER_ADMIN 