"""
Input Validation Middleware
Applies comprehensive input validation to all API requests
"""

import json
import logging
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from django.utils.deprecation import MiddlewareMixin
from django.views.decorators.csrf import csrf_exempt
from django.urls import resolve
from .security import input_validator, csrf_protection
from .validation_schemas import ValidationSchemas

# Security logger
security_logger = logging.getLogger('security')

class InputValidationMiddleware(MiddlewareMixin):
    """
    Middleware to validate and sanitize all input data
    """
    
    # Endpoints that should skip validation (e.g., file uploads, webhooks)
    SKIP_VALIDATION_ENDPOINTS = [
        '/api/auth/health/',
        '/api/admin/',
        '/api/swagger/',
        '/api/redoc/',
        '/media/',
        '/static/',
    ]
    
    # Endpoints that require CSRF protection
    CSRF_PROTECTED_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
    
    def process_request(self, request):
        """Process incoming request for validation"""
        
        # Skip validation for certain endpoints
        if self._should_skip_validation(request):
            return None
        
        # Skip validation for safe methods (GET, HEAD, OPTIONS)
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return None
        
        try:
            # Validate CSRF token for state-changing operations
            if request.method in self.CSRF_PROTECTED_METHODS:
                self._validate_csrf_token(request)
            
            # Get request data
            request_data = self._get_request_data(request)
            
            if request_data:
                # Get validation schema for this endpoint
                schema = self._get_validation_schema(request)
                
                # Validate and sanitize input data
                sanitized_data = input_validator.validate_and_sanitize(request_data, schema)
                
                # Update request with sanitized data
                self._update_request_data(request, sanitized_data)
                
                # Log successful validation
                security_logger.info(f"Input validation successful for {request.method} {request.path}")
        
        except ValidationError as e:
            # Log validation failure
            client_ip = self._get_client_ip(request)
            security_logger.warning(
                f"Input validation failed for {request.method} {request.path} "
                f"from {client_ip}: {str(e)}"
            )
            
            # Return validation error response
            return JsonResponse({
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Input validation failed',
                    'details': e.message_dict if hasattr(e, 'message_dict') else str(e)
                }
            }, status=400)
        
        except Exception as e:
            # Log unexpected validation error
            security_logger.error(f"Unexpected validation error: {str(e)}")
            
            return JsonResponse({
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'An error occurred during input validation'
                }
            }, status=500)
        
        return None
    
    def _should_skip_validation(self, request):
        """Check if validation should be skipped for this request"""
        path = request.path
        
        # Skip validation for specific endpoints
        for skip_path in self.SKIP_VALIDATION_ENDPOINTS:
            if path.startswith(skip_path):
                return True
        
        # Skip validation for non-API endpoints
        if not path.startswith('/api/'):
            return True
        
        return False
    
    def _validate_csrf_token(self, request):
        """Validate CSRF token for state-changing operations"""
        try:
            # Skip CSRF validation for API endpoints with token authentication
            if request.META.get('HTTP_AUTHORIZATION', '').startswith('Token '):
                return
            
            # Skip CSRF validation for endpoints marked as exempt
            resolver_match = resolve(request.path_info)
            if hasattr(resolver_match.func, 'csrf_exempt'):
                return
            
            csrf_protection.validate_csrf_token(request)
            
        except ValidationError as e:
            raise ValidationError({'csrf_token': str(e)})
    
    def _get_request_data(self, request):
        """Extract request data from various sources"""
        request_data = {}
        
        # Get data from POST/PUT/PATCH body
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_type = request.META.get('CONTENT_TYPE', '')
            
            if 'application/json' in content_type:
                try:
                    if hasattr(request, 'body') and request.body:
                        request_data = json.loads(request.body.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    raise ValidationError('Invalid JSON data')
            
            elif 'application/x-www-form-urlencoded' in content_type:
                request_data = dict(request.POST.items())
            
            elif 'multipart/form-data' in content_type:
                # For file uploads, validate text fields only
                request_data = {k: v for k, v in request.POST.items()}
        
        # Add query parameters for all methods
        if request.GET:
            request_data.update(dict(request.GET.items()))
        
        return request_data
    
    def _get_validation_schema(self, request):
        """Get validation schema for the current endpoint"""
        try:
            # Extract endpoint path from URL
            path = request.path.strip('/')
            
            # Remove /api/ prefix if present
            if path.startswith('api/'):
                path = path[4:]
            
            # Remove trailing slashes and IDs
            path_parts = path.split('/')
            
            # Handle detail endpoints (e.g., /users/123/ -> /users)
            if len(path_parts) > 1 and path_parts[-1].isdigit():
                path = '/'.join(path_parts[:-1])
            elif len(path_parts) > 2 and path_parts[-2].isdigit():
                path = '/'.join(path_parts[:-2])
            
            return ValidationSchemas.get_endpoint_schema(path, request.method)
        
        except Exception as e:
            security_logger.warning(f"Could not determine validation schema for {request.path}: {str(e)}")
            return {}
    
    def _update_request_data(self, request, sanitized_data):
        """Update request with sanitized data"""
        if request.method == 'GET':
            # Update GET parameters
            request.GET = request.GET.copy()
            for key, value in sanitized_data.items():
                if key in request.GET:
                    request.GET[key] = value
        
        else:
            # Update POST data
            if hasattr(request, '_body'):
                # Update JSON body
                request._body = json.dumps(sanitized_data).encode('utf-8')
            
            # Update POST QueryDict
            if hasattr(request, 'POST'):
                request.POST = request.POST.copy()
                for key, value in sanitized_data.items():
                    if key in request.POST:
                        request.POST[key] = value
    
    def _get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Enhanced security headers middleware
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
    
    def process_response(self, request, response):
        """Add security headers to response"""
        
        # Content Security Policy
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",  # Adjust as needed
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src 'self' data: blob: https:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ]
        
        response['Content-Security-Policy'] = '; '.join(csp_directives)
        
        # Other security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # HSTS (only for HTTPS)
        if request.is_secure():
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        # Remove server information
        if 'Server' in response:
            del response['Server']
        
        return response


class RateLimitMiddleware(MiddlewareMixin):
    """
    Enhanced rate limiting middleware with distributed support
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
    
    def process_request(self, request):
        """Apply rate limiting to requests"""
        from django.core.cache import cache
        import time
        
        # Skip rate limiting for certain endpoints
        if request.path.startswith('/api/admin/') or request.path.startswith('/static/'):
            return None
        
        client_ip = self._get_client_ip(request)
        
        # Different limits for different endpoint types
        limits = self._get_rate_limits(request)
        
        if not limits:
            return None
        
        # Check rate limit
        cache_key = f"rate_limit:{client_ip}:{request.path}"
        requests = cache.get(cache_key, [])
        
        # Clean old requests
        current_time = time.time()
        requests = [req_time for req_time in requests if current_time - req_time < limits['window']]
        
        # Check if limit exceeded
        if len(requests) >= limits['limit']:
            security_logger.warning(f"Rate limit exceeded for IP {client_ip} on path {request.path}")
            
            return JsonResponse({
                'error': {
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'message': 'Too many requests. Please try again later.',
                    'retry_after': limits['window']
                }
            }, status=429, headers={'Retry-After': str(limits['window'])})
        
        # Record this request
        requests.append(current_time)
        cache.set(cache_key, requests, timeout=limits['window'])
        
        return None
    
    def _get_rate_limits(self, request):
        """Get rate limits for the current request"""
        path = request.path
        method = request.method
        
        # Authentication endpoints (stricter limits)
        if '/auth/login' in path or '/auth/verify-otp' in path:
            return {'limit': 5, 'window': 300}  # 5 per 5 minutes
        
        # Password reset endpoints
        if '/auth/password' in path:
            return {'limit': 3, 'window': 600}  # 3 per 10 minutes
        
        # File upload endpoints
        if method == 'POST' and ('upload' in path or 'file' in path):
            return {'limit': 10, 'window': 60}  # 10 per minute
        
        # General API endpoints
        if path.startswith('/api/'):
            if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                return {'limit': 30, 'window': 60}  # 30 per minute for write operations
            else:
                return {'limit': 100, 'window': 60}  # 100 per minute for read operations
        
        return None
    
    def _get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip