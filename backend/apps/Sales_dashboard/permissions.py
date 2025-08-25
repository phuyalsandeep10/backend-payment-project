import logging
from rest_framework.permissions import BasePermission
from django.contrib.auth.models import AnonymousUser

logger = logging.getLogger(__name__)

class IsSalesperson(BasePermission):
    """
    Custom permission to only allow access to users with the 'Salesperson' role.
    Super Admins have access to all endpoints.
    Enhanced with better logging and case-insensitive role checking.
    """
    def has_permission(self, request, view):
        logger.debug("--- Sales Dashboard Permission Check ---")
        
        # Allow access for superusers
        if request.user and request.user.is_superuser:
            logger.debug("User is a superuser. Access granted.")
            return True
            
        # Deny access for anonymous users
        if isinstance(request.user, AnonymousUser) or not request.user.is_authenticated:
            logger.debug("User is anonymous. Access denied.")
            return False
            
        # Check if user has a role and if that role is 'Salesperson' (case-insensitive)
        if not hasattr(request.user, 'role') or not request.user.role:
            logger.debug(f"User {request.user.email} has no role. Access denied.")
            return False

        # Normalize role name: trim whitespace and compare case-insensitively
        role_name_normalized = request.user.role.name.strip().lower()
        if role_name_normalized not in ['salesperson', 'sales', 'sales-person']:
            logger.debug(
                f"User {request.user.email} role '{request.user.role.name}' is not Salesperson (normalized: '{role_name_normalized}'). Access denied."
            )
            return False
        
        logger.debug(f"User: {request.user.email}, Role: {request.user.role.name}")
        logger.debug("Sales Dashboard access granted.")
        logger.debug("----------------------------------------")
        
        return True 