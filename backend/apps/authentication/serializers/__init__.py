"""
Simplified Authentication Serializers - Task 2.3.3

Organized into focused components with service layer integration.
"""

# Import all serializers for backward compatibility
from .base_serializers import (
    BaseUserSerializer,
    UserLiteSerializer, 
    UserProfileSerializer,
    ProfileMixin,
    RoleMixin,
    OrganizationMixin
)

from .user_serializers import (
    UserSerializer,
    UserDetailSerializer,
    UserCreateSerializer,
    UserUpdateSerializer
)

from .auth_serializers import (
    UserLoginSerializer,
    UserRegistrationSerializer,
    PasswordChangeSerializer,
    PasswordResetSerializer,
    SuperUserLoginSerializer,
    OTPSerializer
)

from .session_serializers import (
    UserSessionSerializer
)

from .response_serializers import (
    AuthSuccessResponseSerializer,
    MessageResponseSerializer,
    ErrorResponseSerializer
)

# Export all for backward compatibility
__all__ = [
    # Base serializers and mixins
    'BaseUserSerializer',
    'UserLiteSerializer',
    'UserProfileSerializer',
    'ProfileMixin',
    'RoleMixin', 
    'OrganizationMixin',
    
    # User management serializers
    'UserSerializer',
    'UserDetailSerializer',
    'UserCreateSerializer', 
    'UserUpdateSerializer',
    
    # Authentication serializers
    'UserLoginSerializer',
    'UserRegistrationSerializer',
    'PasswordChangeSerializer',
    'PasswordResetSerializer',
    'SuperUserLoginSerializer',
    'OTPSerializer',
    
    # Session serializers
    'UserSessionSerializer',
    
    # Response serializers
    'AuthSuccessResponseSerializer',
    'MessageResponseSerializer',
    'ErrorResponseSerializer'
]
