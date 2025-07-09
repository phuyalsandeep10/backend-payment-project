from rest_framework.permissions import BasePermission

class HasClientPermission(BasePermission):
    """
    Custom permission to check for client-related permissions.
    Assumes user is already authenticated.
    """
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True

        if not request.user.role:
            return False

        required_perms_map = {
            'list': ['view_all_clients', 'view_own_clients'],
            'create': ['create_new_client'],
            'retrieve': ['view_all_clients', 'view_own_clients'],
            'update': ['edit_client_details'],
            'partial_update': ['edit_client_details'],
            'destroy': ['remove_client'],
        }
        
        required_perms = required_perms_map.get(view.action, [])
        if not required_perms:
            return False
            
        return request.user.role.permissions.filter(codename__in=required_perms).exists()

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        if obj.organization != request.user.organization:
            return False

        # If user can only see their own, check if they are the creator
        if not request.user.role.permissions.filter(codename='view_all_clients').exists() and \
           request.user.role.permissions.filter(codename='view_own_clients').exists():
            return obj.created_by == request.user
            
        return True 