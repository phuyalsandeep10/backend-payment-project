from rest_framework.permissions import BasePermission, SAFE_METHODS

class HasPermission(BasePermission):
    """
    Custom permission to check if a user's role has the required permission.
    Permissions are mapped to view actions.
    """
    def has_permission(self, request, view):
        # Always allow for superusers
        if request.user and request.user.is_superuser:
            return True

        # Deny if user or role is not set
        if not request.user or not request.user.role:
            return False

        # Map view actions to permission codenames based on viewset type
        viewset_name = view.__class__.__name__
        action = getattr(view, 'action', None)
        
        if viewset_name == 'DealViewSet':
            required_perms_map = {
                'list': ['view_all_deals', 'view_own_deals'],
                'create': ['create_deal'],
                'retrieve': ['view_all_deals', 'view_own_deals'],
                'update': ['update_deal_status'],
                'partial_update': ['update_deal_status'],
                'destroy': [], # Define if needed
                'log_activity': ['log_deal_activity'],
            }
        elif viewset_name == 'PaymentViewSet':
            required_perms_map = {
                'list': ['verify_deal_payment', 'view_all_deals'],
                'create': ['verify_deal_payment'],
                'retrieve': ['verify_deal_payment', 'view_all_deals'],
                'update': ['verify_deal_payment'],
                'partial_update': ['verify_deal_payment'],
                'destroy': ['verify_deal_payment'],
            }
        elif viewset_name == 'ActivityLogViewSet':
            # For ReadOnlyModelViewSet, allow all HTTP methods through to the viewset level
            # so that DRF can properly return 405 for unsupported methods
            required_perms_map = {
                'list': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],
                'retrieve': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],
                'create': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],  # Allow through for proper 405
                'update': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],  # Allow through for proper 405
                'partial_update': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],  # Allow through for proper 405
                'destroy': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],  # Allow through for proper 405
            }
        else:
            required_perms_map = {}
        
        required_perms = required_perms_map.get(action, [])
        
        # If no specific permission is required for an action, deny by default
        if not required_perms:
            return False
            
        # Check if the user's role has any of the required permissions
        return request.user.role.permissions.filter(codename__in=required_perms).exists()

    def has_object_permission(self, request, view, obj):
        # Always allow for superusers
        if request.user and request.user.is_superuser:
            return True

        # Deny if user or role is not set
        if not request.user or not request.user.role:
            return False

        # Object-level check: ensure user belongs to the same organization as the deal
        if obj.organization != request.user.organization:
            return False

        # If user only has 'view_own_deals', check if they created the deal
        if not request.user.role.permissions.filter(codename='view_all_deals').exists() and \
           request.user.role.permissions.filter(codename='view_own_deals').exists():
            return obj.created_by == request.user
            
        return True 