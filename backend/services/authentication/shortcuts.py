"""
Authentication Service Shortcuts - Task 2.3.1 & 2.3.2

Provides easy access to authentication services for backward compatibility
and convenient imports in authentication app.
"""

from services.service_registry import ServiceRegistry

# Get service registry instance
_registry = ServiceRegistry()

# Authentication service shortcuts
def get_password_policy_service():
    """Get password policy service instance"""
    return _registry.get_service('password_policy_service')

def get_session_management_service():
    """Get session management service instance"""
    return _registry.get_service('session_management_service')

def get_security_event_service():
    """Get security event service instance"""
    return _registry.get_service('security_event_service')

def get_user_profile_service():
    """Get user profile service instance"""
    return _registry.get_service('user_profile_service')

def get_user_role_service():
    """Get user role service instance"""
    return _registry.get_service('user_role_service')

def get_user_organization_service():
    """Get user organization service instance"""
    return _registry.get_service('user_organization_service')

def get_user_relationship_service():
    """Get user relationship service instance"""
    return _registry.get_service('user_relationship_service')

# Backward compatibility aliases
password_policy_service = get_password_policy_service()
session_service = get_session_management_service()
security_event_logger = get_security_event_service()  # Maintains existing naming convention

# New service aliases (Task 2.3.2)
user_profile_service = get_user_profile_service()
user_role_service = get_user_role_service()
user_organization_service = get_user_organization_service()
user_relationship_service = get_user_relationship_service()
