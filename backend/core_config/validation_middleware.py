"""
Input Validation Middleware

This middleware automatically validates and sanitizes all incoming requests
to prevent security vulnerabilities and ensure data integrity.
"""

import json
import logging
from typing import Dict, Any, Optional
from django.http import JsonResponse, HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .input_validation_service import input_validator, ValidationResult
from .validation_schemas import get_schema

logger = logging.getLogger(__name__)


class InputValidationMiddleware(MiddlewareMixin):
    """
    Middleware to validate and sanitize all incoming requests
    """
    
    # Endpoints that should be exempt from validation
    EXEMPT_PATHS = [
        '/admin/',
        '/static/',
        '/media/',
        '/health/',
        '/metrics/',
        '/api/docs/',
        '/api/schema/',
    ]
    
    # Methods that require CSRF validation
    CSRF_REQUIRED_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    
    # Endpoints that are exempt from CSRF validation
    CSRF_EXEMPT_PATHS = [
        '/api/auth/login/',
        '/api/auth/register/',
        '/api/auth/password-reset/',
        '/api/webhooks/',
    ]
    
    def __init__(self, get_response):
        """Initialize the middleware"""
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming request for validation
        
        Args:
            request: Django HTTP request
            
        Returns:
            HttpResponse if validation fails, None otherwise
        """
        # Skip validation for exempt paths
        if self._is_exempt_path(request.path):
            return None
        
        # Skip validation for safe methods (GET, HEAD, OPTIONS)
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return None
        
        try:
            # Validate CSRF token for state-changing operations
            csrf_result = self._validate_csrf_token(request)
            if csrf_result:
                return csrf_result
            
            # Parse and validate request data
            validation_result = self._validate_request_data(request)
            if not validation_result.is_valid:
                return self._create_validation_error_response(validation_result)
            
            # Store sanitized data in request for use by views
            request.validated_data = validation_result.sanitized_data
            
        except Exception as e:
            logger.error(f"Error in input validation middleware: {str(e)}")
            return JsonResponse({
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Request validation failed',
                    'timestamp': self._get_timestamp()
                }
            }, status=400)
        
        return None
    
    def _is_exempt_path(self, path: str) -> bool:
        """
        Check if path is exempt from validation
        
        Args:
            path: Request path
            
        Returns:
            True if path is exempt
        """
        return any(path.startswith(exempt_path) for exempt_path in self.EXEMPT_PATHS)
    
    def _validate_csrf_token(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Validate CSRF token for state-changing operations
        
        Args:
            request: Django HTTP request
            
        Returns:
            HttpResponse if CSRF validation fails, None otherwise
        """
        # Skip CSRF validation for exempt paths
        if any(request.path.startswith(path) for path in self.CSRF_EXEMPT_PATHS):
            return None
        
        # Skip CSRF validation for safe methods
        if request.method not in self.CSRF_REQUIRED_METHODS:
            return None
        
        # Get CSRF token from headers or form data
        csrf_token = (
            request.META.get('HTTP_X_CSRFTOKEN') or
            request.META.get('HTTP_X_CSRF_TOKEN') or
            request.POST.get('csrfmiddlewaretoken')
        )
        
        if not csrf_token:
            logger.warning(f"Missing CSRF token for {request.method} {request.path}")
            input_validator.create_security_event_log(
                'CSRF_TOKEN_MISSING',
                request,
                {'path': request.path, 'method': request.method}
            )
            return JsonResponse({
                'error': {
                    'code': 'CSRF_TOKEN_MISSING',
                    'message': 'CSRF token is required for this operation',
                    'timestamp': self._get_timestamp()
                }
            }, status=403)
        
        # Validate CSRF token
        if not input_validator.validate_csrf_token(request, csrf_token):
            logger.warning(f"Invalid CSRF token for {request.method} {request.path}")
            input_validator.create_security_event_log(
                'CSRF_TOKEN_INVALID',
                request,
                {'path': request.path, 'method': request.method}
            )
            return JsonResponse({
                'error': {
                    'code': 'CSRF_TOKEN_INVALID',
                    'message': 'Invalid CSRF token',
                    'timestamp': self._get_timestamp()
                }
            }, status=403)
        
        return None
    
    def _validate_request_data(self, request: HttpRequest) -> ValidationResult:
        """
        Validate and sanitize request data
        
        Args:
            request: Django HTTP request
            
        Returns:
            ValidationResult
        """
        # Get request data based on content type
        request_data = self._extract_request_data(request)
        
        # Get validation schema for the endpoint
        schema = self._get_endpoint_schema(request)
        
        # Validate and sanitize the data
        return input_validator.validate_and_sanitize(request_data, schema)
    
    def _extract_request_data(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Extract data from request based on content type
        
        Args:
            request: Django HTTP request
            
        Returns:
            Dictionary of request data
        """
        request_data = {}
        
        try:
            # Handle JSON data
            if request.content_type == 'application/json':
                if hasattr(request, 'body') and request.body:
                    request_data = json.loads(request.body.decode('utf-8'))
            
            # Handle form data
            elif request.content_type in ['application/x-www-form-urlencoded', 'multipart/form-data']:
                request_data = dict(request.POST)
                
                # Handle file uploads
                if request.FILES:
                    for key, file in request.FILES.items():
                        request_data[key] = {
                            'name': file.name,
                            'size': file.size,
                            'content_type': file.content_type
                        }
            
            # Handle query parameters for all requests
            if request.GET:
                request_data.update(dict(request.GET))
            
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Error parsing request data: {str(e)}")
            # Return empty dict to trigger validation error
            request_data = {'_parse_error': str(e)}
        
        return request_data
    
    def _get_endpoint_schema(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Get validation schema for the current endpoint
        
        Args:
            request: Django HTTP request
            
        Returns:
            Validation schema dictionary
        """
        # Map request path and method to schema name
        path = request.path.rstrip('/')
        method = request.method.lower()
        
        # Define endpoint mappings
        endpoint_mappings = {
            ('/api/auth/login', 'post'): 'login',
            ('/api/auth/register', 'post'): 'register',
            ('/api/auth/password-reset', 'post'): 'password_reset_request',
            ('/api/auth/password-reset/confirm', 'post'): 'password_reset_confirm',
            ('/api/auth/change-password', 'post'): 'change_password',
            ('/api/auth/otp/verify', 'post'): 'otp_verify',
            ('/api/users/profile', 'put'): 'profile_update',
            ('/api/users/profile', 'patch'): 'profile_update',
            ('/api/users', 'post'): 'user_create',
            ('/api/deals', 'post'): 'deal_create',
            ('/api/deals/\\d+', 'put'): 'deal_update',
            ('/api/deals/\\d+', 'patch'): 'deal_update',
            ('/api/payments', 'post'): 'payment_create',
            ('/api/files/upload', 'post'): 'file_upload',
            ('/api/files/bulk-upload', 'post'): 'bulk_upload',
            ('/api/organizations', 'post'): 'organization_create',
            ('/api/organizations/\\d+', 'put'): 'organization_update',
            ('/api/organizations/\\d+', 'patch'): 'organization_update',
            ('/api/clients', 'post'): 'client_create',
            ('/api/clients/\\d+', 'put'): 'client_update',
            ('/api/clients/\\d+', 'patch'): 'client_update',
            ('/api/search', 'get'): 'search',
            ('/api/search', 'post'): 'search',
            ('/api/reports/generate', 'post'): 'report_generate',
        }
        
        # Find matching endpoint
        for (endpoint_path, endpoint_method), schema_name in endpoint_mappings.items():
            if method == endpoint_method:
                # Handle regex patterns for dynamic URLs
                if '\\d+' in endpoint_path:
                    import re
                    pattern = endpoint_path.replace('\\d+', '\\d+')
                    if re.match(pattern, path):
                        return get_schema(schema_name)
                elif path == endpoint_path:
                    return get_schema(schema_name)
        
        # Return empty schema if no match found
        return {}
    
    def _create_validation_error_response(self, validation_result: ValidationResult) -> HttpResponse:
        """
        Create error response for validation failures
        
        Args:
            validation_result: Validation result with errors
            
        Returns:
            JSON error response
        """
        return JsonResponse({
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'Request validation failed',
                'details': validation_result.errors,
                'timestamp': self._get_timestamp()
            }
        }, status=400)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from django.utils import timezone
        return timezone.now().isoformat()


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware to add security headers to all responses
    """
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Add security headers to response
        
        Args:
            request: Django HTTP request
            response: Django HTTP response
            
        Returns:
            Modified response with security headers
        """
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Add HSTS header for HTTPS
        if request.is_secure():
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Add CSP header
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https:; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none';"
        )
        response['Content-Security-Policy'] = csp_policy
        
        return response


class RateLimitMiddleware(MiddlewareMixin):
    """
    Middleware to implement rate limiting
    """
    
    def __init__(self, get_response):
        """Initialize the middleware"""
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Check rate limits for the request
        
        Args:
            request: Django HTTP request
            
        Returns:
            HttpResponse if rate limit exceeded, None otherwise
        """
        try:
            # Get client IP
            client_ip = self._get_client_ip(request)
            
            # Check rate limit
            if self._is_rate_limited(client_ip, request.path):
                logger.warning(f"Rate limit exceeded for IP {client_ip} on {request.path}")
                input_validator.create_security_event_log(
                    'RATE_LIMIT_EXCEEDED',
                    request,
                    {'client_ip': client_ip, 'path': request.path}
                )
                return JsonResponse({
                    'error': {
                        'code': 'RATE_LIMIT_EXCEEDED',
                        'message': 'Too many requests. Please try again later.',
                        'timestamp': self._get_timestamp()
                    }
                }, status=429)
        
        except Exception as e:
            logger.error(f"Error in rate limit middleware: {str(e)}")
        
        return None
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address from request
        
        Args:
            request: Django HTTP request
            
        Returns:
            Client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')
    
    def _is_rate_limited(self, client_ip: str, path: str) -> bool:
        """
        Check if client IP is rate limited for the given path
        
        Args:
            client_ip: Client IP address
            path: Request path
            
        Returns:
            True if rate limited
        """
        try:
            import redis
            from django.conf import settings
            
            # Connect to Redis
            redis_client = redis.Redis(
                host=getattr(settings, 'REDIS_HOST', 'localhost'),
                port=getattr(settings, 'REDIS_PORT', 6379),
                db=getattr(settings, 'REDIS_DB', 0)
            )
            
            # Define rate limits (requests per minute)
            rate_limits = {
                '/api/auth/login': 5,
                '/api/auth/register': 3,
                '/api/auth/password-reset': 3,
                'default': 60
            }
            
            # Get rate limit for path
            limit = rate_limits.get(path, rate_limits['default'])
            
            # Create Redis key
            key = f"rate_limit:{client_ip}:{path}"
            
            # Get current count
            current_count = redis_client.get(key)
            
            if current_count is None:
                # First request, set count to 1 with 60 second expiry
                redis_client.setex(key, 60, 1)
                return False
            
            current_count = int(current_count)
            
            if current_count >= limit:
                return True
            
            # Increment count
            redis_client.incr(key)
            return False
        
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            # Allow request if rate limiting fails
            return False
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from django.utils import timezone
        return timezone.now().isoformat()