"""
Authentication Services Integration - Task 2.3.1 & 2.3.2

This module provides convenient access to the extracted authentication services
for use within the authentication app. Maintains backward compatibility while
enabling the new service-oriented architecture and reducing User model coupling.
"""

# Import services from the service layer
from services.authentication.shortcuts import (
    get_password_policy_service,
    get_session_management_service, 
    get_security_event_service,
    get_user_profile_service,
    get_user_role_service,
    get_user_organization_service,
    get_user_relationship_service,
    password_policy_service,
    session_service,
    security_event_logger,
    user_profile_service,
    user_role_service,
    user_organization_service,
    user_relationship_service
)

# Backward compatibility - maintain existing naming conventions
password_policy = password_policy_service
session_manager = session_service
security_logger = security_event_logger

# New service aliases for reducing User model coupling (Task 2.3.2)
profile_service = user_profile_service
role_service = user_role_service
organization_service = user_organization_service
relationship_service = user_relationship_service

# Export public interface
__all__ = [
    # Service getters
    'get_password_policy_service',
    'get_session_management_service',
    'get_security_event_service',
    'get_user_profile_service',
    'get_user_role_service', 
    'get_user_organization_service',
    'get_user_relationship_service',
    
    # Direct service instances
    'password_policy_service',
    'session_service',
    'security_event_logger',
    'user_profile_service',
    'user_role_service',
    'user_organization_service',
    'user_relationship_service',
    
    # Backward compatibility aliases
    'password_policy',
    'session_manager',
    'security_logger',
    
    # New aliases for reduced coupling
    'profile_service',
    'role_service',
    'organization_service',
    'relationship_service'
]
