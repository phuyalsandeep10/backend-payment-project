"""
Authentication Utilities and Helper Functions

This module contains utility functions and throttle classes for authentication.
Extracted from views.py for better organization and reduced complexity.
"""

import logging
from rest_framework.throttling import AnonRateThrottle
from .models import UserSession

# Security logger
security_logger = logging.getLogger('security')


def get_client_ip(request):
    """Get client IP address from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def _create_user_session(request, user, token_key):
    """Helper to create or update a UserSession record on login."""
    UserSession.objects.update_or_create(
        session_key=token_key,
        defaults={
            'user': user,
            'ip_address': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')
        }
    )


class LoginRateThrottle(AnonRateThrottle):
    """Rate limiting for login attempts."""
    scope = 'login'


class OTPThrottle(AnonRateThrottle):
    """Rate limiting for OTP verification attempts."""
    scope = 'otp'
