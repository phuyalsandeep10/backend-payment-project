from rest_framework.permissions import BasePermission

class IsSalesperson(BasePermission):
    """
    Custom permission to only allow access to users with the 'Salesperson' role.
    Super Admins have access to all endpoints.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Superusers have access everywhere
        if request.user.is_superuser:
            return True
            
        return hasattr(request.user, 'role') and request.user.role and request.user.role.name == 'Salesperson' 