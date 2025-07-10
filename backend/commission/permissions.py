from rest_framework.permissions import BasePermission

class HasCommissionPermission(BasePermission):
    """
    Custom permission to check for commission-related permissions.
    """
    def has_permission(self, request, view):
        if request.user and request.user.is_superuser:
            return True

        if not request.user or not request.user.is_authenticated or not getattr(request.user, 'role', None):
            return False

        required_perms_map = {
            'list': ['view_all_commissions', 'view_commission'],
            'create': ['add_commission'],
            'retrieve': ['view_all_commissions', 'view_commission'],
            'update': ['edit_commission'],
            'partial_update': ['edit_commission'],
            'destroy': ['delete_commission'],
        }
        
        required_perms = required_perms_map.get(view.action, [])
        if not required_perms:
            return False
            
        return request.user.role.permissions.filter(codename__in=required_perms).exists()

    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_superuser:
            return True

        if not request.user or not request.user.is_authenticated or not getattr(request.user, 'role', None):
            return False

        if obj.organization != request.user.organization:
            return False
            
        return True 