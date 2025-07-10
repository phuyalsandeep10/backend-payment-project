from rest_framework.permissions import BasePermission, SAFE_METHODS

class HasPermission(BasePermission):
    """
    Custom permission to check if a user's role has the required permission.
    Permissions are mapped to view actions.
    """
    def has_permission(self, request, view):
        # Deny if user is not authenticated
        if not request.user or not request.user.is_authenticated:
            return False

        # Always allow for superusers
        if request.user.is_superuser:
            return True

        # Deny if user role is not set
        if not request.user.role:
            return False

        # Map view actions to permission codenames based on viewset type
        viewset_name = view.__class__.__name__
        action = getattr(view, 'action', None)
        
        if viewset_name == 'DealViewSet':
            required_perms_map = {
                'list': ['view_all_deals', 'view_own_deals'],
                'create': ['create_deal'],
                'retrieve': ['view_all_deals', 'view_own_deals'],
                'expand': ['view_all_deals', 'view_own_deals'],
                'list_invoices': ['view_all_deals', 'view_own_deals'],
                'update': ['edit_deal'],
                'partial_update': ['edit_deal'],
                'destroy': ['delete_deal'],
                'log_activity': ['log_deal_activity'],
            }
        elif viewset_name == 'PaymentViewSet':
            required_perms_map = {
                'list': ['verify_deal_payment', 'view_all_deals', 'create_deal_payment'],
                'create': ['verify_deal_payment', 'create_deal_payment'],
                'retrieve': ['verify_deal_payment', 'view_all_deals', 'create_deal_payment'],
                'update': ['verify_deal_payment'],
                'partial_update': ['verify_deal_payment'],
                'destroy': ['verify_deal_payment'],
                'verify': ['verify_deal_payment'],
            }
        elif viewset_name == 'ActivityLogViewSet':
            # For ReadOnlyModelViewSet, allow all HTTP methods through to the viewset level
            # so that DRF can properly return 405 for unsupported methods
            required_perms_map = {
                'list': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],
                'retrieve': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],
                'create': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],
                'update': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],
                'partial_update': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],
                'destroy': ['view_all_deals', 'view_own_deals', 'log_deal_activity'],
            }
        elif viewset_name == 'PaymentInvoiceViewSet':
            required_perms_map = {
                'list': ['view_paymentinvoice', 'view_all_deals'],
                'create': ['create_paymentinvoice'],
                'retrieve': ['view_paymentinvoice', 'view_all_deals'],
                'update': ['edit_paymentinvoice'],
                'partial_update': ['edit_paymentinvoice'],
                'destroy': ['delete_paymentinvoice'],
            }
        elif viewset_name == 'PaymentApprovalViewSet':
            required_perms_map = {
                'list': ['view_paymentapproval', 'view_all_deals'],
                'create': ['create_paymentapproval'],
                'retrieve': ['view_paymentapproval', 'view_all_deals'],
                'update': ['edit_paymentapproval'],
                'partial_update': ['edit_paymentapproval'],
                'destroy': ['delete_paymentapproval'],
            }
        else:
            required_perms_map = {}
        
        required_perms = required_perms_map.get(action, [])
        
        # If no specific permission is required for an action, deny by default
        if not required_perms:
            return False
            
        # If 'view_own_deals' is one of the required permissions, and the user has it,
        # defer the final decision to `has_object_permission`.
        if 'view_own_deals' in required_perms and request.user.role.permissions.filter(codename='view_own_deals').exists():
            return True

        # Check if the user's role has any of the required permissions for other cases
        return request.user.role.permissions.filter(codename__in=required_perms).exists()

    def has_object_permission(self, request, view, obj):
        # Always allow for superusers
        if request.user and request.user.is_superuser:
            return True

        # Deny if user or role is not set
        if not request.user or not request.user.role:
            return False

        # Get organization from the object based on its type
        if hasattr(obj, 'organization'):
            # Deal objects have direct organization attribute
            obj_organization = obj.organization
        elif hasattr(obj, 'deal') and hasattr(obj.deal, 'organization'):
            # Payment, PaymentInvoice and PaymentApproval objects have organization through deal
            obj_organization = obj.deal.organization
        else:
            # For other objects, deny access
            return False

        # Object-level check: ensure user belongs to the same organization as the object
        if obj_organization != request.user.organization:
            return False

        # If user only has 'view_own_deals', check if they created the deal
        if not request.user.role.permissions.filter(codename='view_all_deals').exists() and \
           request.user.role.permissions.filter(codename='view_own_deals').exists():
            # For Deal objects, check created_by
            if hasattr(obj, 'created_by'):
                return obj.created_by == request.user
            # For related objects, check the deal's created_by
            elif hasattr(obj, 'deal') and hasattr(obj.deal, 'created_by'):
                return obj.deal.created_by == request.user
            else:
                return False
            
        return True 