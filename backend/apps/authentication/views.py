"""
Authentication Views - Refactored Module

This file serves as the main entry point for authentication views,
importing from modular view files for better organization.

The original 1165-line views.py file has been broken down into:
- auth_views.py: Authentication flows (login, logout, OTP, registration)
- user_views.py: User management (UserViewSet and related functionality)
- session_views.py: Session management (UserSessionViewSet)
- profile_views.py: User profile and preferences management
- auth_utils.py: Utility functions and throttle classes

This refactoring reduces complexity and improves maintainability.
"""

# Import all views from modular files for backward compatibility
from .auth_views import (
    login_view,
    logout_view,
    verify_otp_view,
    super_admin_login_view,
    super_admin_verify_view,
    org_admin_login_view,
    org_admin_verify_view,
    password_change_view,
    password_change_with_token_view,
    register_view,
    health_check,
    login_stats_view
)

from .user_views import (
    UserViewSet
)

from .session_views import (
    UserSessionViewSet,
    test_email_outbox_view
)

from .profile_views import (
    UserProfileView,
    UserNotificationPreferencesView,
    set_sales_target_view
)

from .auth_utils import (
    get_client_ip,
    LoginRateThrottle,
    OTPThrottle
)

# Make all imports available at module level for backward compatibility
__all__ = [
    # Authentication views
    'login_view',
    'logout_view', 
    'verify_otp_view',
    'super_admin_login_view',
    'super_admin_verify_view',
    'org_admin_login_view',
    'org_admin_verify_view',
    'password_change_view',
    'password_change_with_token_view',
    'register_view',
    'health_check',
    'login_stats_view',
    
    # User management views
    'UserViewSet',
    
    # Session management views
    'UserSessionViewSet',
    'test_email_outbox_view',
    
    # Profile management views
    'UserProfileView',
    'UserNotificationPreferencesView', 
    'set_sales_target_view',
    
    # Utility functions and classes
    'get_client_ip',
    'LoginRateThrottle',
    'OTPThrottle'
]
