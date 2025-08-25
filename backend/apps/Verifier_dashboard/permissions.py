import logging
from rest_framework.permissions import BasePermission
from django.contrib.auth.models import AnonymousUser

logger = logging.getLogger(__name__)

class HasVerifierPermission(BasePermission):
    """
    Custom permission class for Verifier Dashboard.
    Checks if user has the required verifier permissions.
    """
    
    # Map view actions to required permissions
    permission_map = {
        # Dashboard views
        'payment_stats': ['view_payment_verification_dashboard'],
        'payment_failure_reasons': ['view_payment_analytics'],
        'payment_methods': ['view_payment_analytics'],
        'payment_status_distribution': ['view_payment_analytics'],
        'invoice_status_overview': ['view_payment_analytics'],
        
        # Invoice management views
        'verifier_invoice': ['manage_invoices'],
        'verifier_pending': ['access_verification_queue'],
        'verifier_verified': ['manage_invoices'],
        'verifier_rejected': ['manage_invoices'],
        'verifier_invoice_delete': ['manage_invoices'],
        
        # Verification views
        'verification_queue': ['access_verification_queue'],
        'payment_verifier_form': ['verify_deal_payment'],
        
        # Refund and bad debt views
        'refunded_invoice': ['manage_refunds'],
        'bad_debt_invoice': ['manage_refunds'],
        'recent_refund_or_bad_debt': ['manage_refunds'],
        
        # Audit logs
        'audit_logs': ['view_audit_logs'],
        
        # ViewSet actions
        'list': ['view_payment_verification_dashboard'],
        'retrieve': ['view_payment_verification_dashboard'],
        'create': ['verify_payments'],
        'update': ['verify_payments'],
        'partial_update': ['verify_payments'],
        'destroy': ['manage_invoices'],
    }

    def has_permission(self, request, view):
        logger.debug("--- Verifier Permission Check ---")
        # Allow access for superusers
        if request.user and request.user.is_superuser:
            logger.debug("User is a superuser. Access granted.")
            return True
            
        # Deny access for anonymous users
        if isinstance(request.user, AnonymousUser) or not request.user.is_authenticated:
            logger.debug("User is anonymous. Access denied.")
            return False
            
        # Check if user has a role and if that role is 'Verifier' (case-insensitive)
        if not hasattr(request.user, 'role') or not request.user.role:
            logger.debug(f"User {request.user.email} has no role. Access denied.")
            return False

        # Normalise role name: trim whitespace and compare case-insensitively
        role_name_normalized = request.user.role.name.strip().lower()
        if role_name_normalized != 'verifier':
            logger.debug(
                f"User {request.user.email} role '{request.user.role.name}' is not Verifier (normalised: '{role_name_normalized}'). Access denied."
            )
            return False
        
        logger.debug(f"User: {request.user.email}, Role: {request.user.role.name}")
            
        # For swagger schema generation, allow access
        if getattr(view, 'swagger_fake_view', False):
            logger.debug("Swagger fake view. Access granted.")
            return True
            
        # Get the view function name or action
        view_name = getattr(view, 'action', None) or view.__class__.__name__.lower()
        if hasattr(view, '__name__'):
            view_name = view.__name__
        
        logger.debug(f"View name: '{view_name}'")
            
        # Get required permissions for this view
        required_permissions = self.permission_map.get(view_name, [])
        logger.debug(f"Required permissions for this view: {required_permissions}")
        
        # If no specific permissions required, allow access
        if not required_permissions:
            logger.debug("No specific permissions required for this view. Access granted.")
            return True
            
        # Check if user has any of the required permissions
        user_permissions = list(request.user.role.permissions.values_list('codename', flat=True))
        logger.debug(f"User's permissions: {user_permissions}")

        has_perm = any(perm in user_permissions for perm in required_permissions)
        
        logger.debug(f"Permission check result: {'Access Granted' if has_perm else 'Access DENIED'}")
        logger.debug("---------------------------------")

        return has_perm
        
    def has_object_permission(self, request, view, obj):
        # Always allow for superusers
        if request.user and request.user.is_superuser:
            return True
            
        # Deny if user or role is not set
        if not request.user or not request.user.role:
            return False
            
        # For models with organization field, check organization match
        if hasattr(obj, 'organization') and obj.organization:
            return obj.organization == request.user.organization
            
        # For models related to deals, check through the deal's organization
        if hasattr(obj, 'deal') and obj.deal and hasattr(obj.deal, 'organization'):
            return obj.deal.organization == request.user.organization
            
        # For models related to payments, check through payment -> deal -> organization
        if hasattr(obj, 'payment') and obj.payment and hasattr(obj.payment, 'deal'):
            return obj.payment.deal.organization == request.user.organization
            
        return True


class IsVerifier(BasePermission):
    """
    Simple permission class to check if user is a verifier.
    """
    
    def has_permission(self, request, view):
        if request.user and request.user.is_superuser:
            return True
            
        if isinstance(request.user, AnonymousUser) or not request.user.is_authenticated:
            return False
            
        if not hasattr(request.user, 'role') or not request.user.role:
            return False
            
        # For swagger schema generation, allow access
        if getattr(view, 'swagger_fake_view', False):
            return True
            
        # Check if user has any verifier permission
        verifier_permissions = [
            'view_payment_verification_dashboard',
            'verify_deal_payment',
        ]
        
        user_permissions = request.user.role.permissions.values_list('codename', flat=True)
        return any(perm in user_permissions for perm in verifier_permissions) 