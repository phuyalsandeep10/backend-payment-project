"""
Enhanced Authentication Middleware
Provides better handling of authentication errors and unauthorized access attempts
"""

import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
from django.urls import resolve

logger = logging.getLogger(__name__)
User = get_user_model()

class EnhancedAuthMiddleware(MiddlewareMixin):
    """
    Enhanced authentication middleware that provides better error handling
    and prevents unauthorized access attempts to protected endpoints.
    """

    # Endpoints that require authentication
    PROTECTED_ENDPOINTS = [
        'api:verifier',
        'api:sales_dashboard', 
        'api:deals',
        'api:commission',
        'api:clients',
        'api:notifications',
        'api:organizations',
        'api:team',
        'api:permissions',
    ]

    # Endpoints that are publicly accessible
    PUBLIC_ENDPOINTS = [
        'api-root',
        'root',
        'health',
        'schema-swagger-ui',
        'schema-redoc',
        'schema-json',
        'authentication:login',
        'authentication:register',
        'authentication:password-reset',
    ]

    def process_request(self, request):
        """
        Process the request before it reaches the view.
        """
        # Skip processing for non-API endpoints
        if not request.path.startswith('/api/'):
            return None

        # Get the resolved URL name
        try:
            resolved = resolve(request.path)
            url_name = resolved.url_name
            namespace = resolved.namespace
            full_url_name = f"{namespace}:{url_name}" if namespace else url_name
        except Exception:
            # If URL cannot be resolved, allow it to pass through
            return None

        # Allow public endpoints
        if full_url_name in self.PUBLIC_ENDPOINTS or url_name in ['api-root', 'health']:
            return None

        # Check if endpoint requires authentication
        requires_auth = any(
            full_url_name.startswith(protected) 
            for protected in self.PROTECTED_ENDPOINTS
        )

        if not requires_auth:
            return None

        # Check for authentication token
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header:
            logger.warning(
                f"Unauthorized access attempt to {request.path} from {self.get_client_ip(request)} - No authorization header"
            )
            return JsonResponse({
                'error': 'Authentication credentials were not provided.',
                'code': 'authentication_required',
                'detail': 'This endpoint requires authentication. Please provide a valid token.'
            }, status=401)

        if not auth_header.startswith('Token '):
            logger.warning(
                f"Invalid authorization header format for {request.path} from {self.get_client_ip(request)}"
            )
            return JsonResponse({
                'error': 'Invalid authentication credentials format.',
                'code': 'invalid_token_format',
                'detail': 'Token should be provided in format: "Token <your_token>"'
            }, status=401)

        # Extract and validate token
        token_value = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else ''
        
        if not token_value:
            return JsonResponse({
                'error': 'Empty authentication token.',
                'code': 'empty_token',
                'detail': 'Authentication token cannot be empty.'
            }, status=401)

        try:
            # Validate token exists and is active
            token = Token.objects.select_related('user').get(key=token_value)
            
            if not token.user.is_active:
                logger.warning(
                    f"Inactive user {token.user.email} attempted to access {request.path}"
                )
                return JsonResponse({
                    'error': 'User account is inactive.',
                    'code': 'inactive_user',
                    'detail': 'Your account has been deactivated. Please contact support.'
                }, status=401)

            # Attach user to request for downstream processing
            request.user = token.user
            
        except Token.DoesNotExist:
            logger.warning(
                f"Invalid token used for {request.path} from {self.get_client_ip(request)}"
            )
            return JsonResponse({
                'error': 'Invalid authentication token.',
                'code': 'invalid_token',
                'detail': 'The provided authentication token is invalid or expired.'
            }, status=401)
        except Exception as e:
            logger.error(f"Authentication error for {request.path}: {e}")
            return JsonResponse({
                'error': 'Authentication verification failed.',
                'code': 'auth_verification_error',
                'detail': 'Unable to verify authentication credentials.'
            }, status=500)

        return None

    def process_response(self, request, response):
        """
        Process the response before it's sent to the client.
        """
        # Add security headers for API responses
        if request.path.startswith('/api/'):
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-Frame-Options'] = 'DENY'
            response['X-XSS-Protection'] = '1; mode=block'
            
            # Add CORS headers for authenticated requests
            if hasattr(request, 'user') and request.user.is_authenticated:
                response['Access-Control-Allow-Credentials'] = 'true'

        return response

    def get_client_ip(self, request):
        """
        Get the client's IP address from the request.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip