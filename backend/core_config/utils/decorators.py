"""
Security decorators for views and API endpoints
"""

import functools
import json
import logging
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from core.security.input_validation_service import input_validator
from core.security.security import csrf_protection

# Security logger
security_logger = logging.getLogger('security')


def validate_input(schema_name=None, schema=None, require_csrf=True):
    """
    Decorator to validate input data for views
    
    Args:
        schema_name: Name of predefined schema from ValidationSchemas
        schema: Custom validation schema dictionary
        require_csrf: Whether to require CSRF token validation
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            try:
                # Skip validation for safe methods
                if request.method in ['GET', 'HEAD', 'OPTIONS']:
                    return view_func(request, *args, **kwargs)
                
                # Validate CSRF token if required
                if require_csrf and request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                    # Skip CSRF for API endpoints with token auth
                    if not request.META.get('HTTP_AUTHORIZATION', '').startswith('Token '):
                        csrf_protection.validate_csrf_token(request)
                
                # Get validation schema
                validation_schema = None
                if schema_name:
                    validation_schema = ValidationSchemas.get_schema(schema_name)
                elif schema:
                    validation_schema = schema
                
                if validation_schema:
                    # Get request data
                    request_data = _get_request_data(request)
                    
                    if request_data:
                        # Validate and sanitize
                        sanitized_data = input_validator.validate_and_sanitize(
                            request_data, validation_schema
                        )
                        
                        # Update request with sanitized data
                        _update_request_data(request, sanitized_data)
                
                return view_func(request, *args, **kwargs)
                
            except ValidationError as e:
                security_logger.warning(
                    f"Input validation failed for {request.method} {request.path}: {str(e)}"
                )
                
                return JsonResponse({
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'Input validation failed',
                        'details': e.message_dict if hasattr(e, 'message_dict') else str(e)
                    }
                }, status=400)
            
            except Exception as e:
                security_logger.error(f"Unexpected validation error: {str(e)}")
                
                return JsonResponse({
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'An error occurred during input validation'
                    }
                }, status=500)
        
        return wrapper
    return decorator


def require_secure_headers(view_func):
    """
    Decorator to add security headers to view responses
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        response = view_func(request, *args, **kwargs)
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response
    
    return wrapper


def rate_limit(limit=60, window=60, key_func=None):
    """
    Decorator to apply rate limiting to views
    
    Args:
        limit: Number of requests allowed
        window: Time window in seconds
        key_func: Function to generate cache key (default: IP-based)
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            from django.core.cache import cache
            import time
            
            # Generate cache key
            if key_func:
                cache_key = key_func(request)
            else:
                client_ip = _get_client_ip(request)
                cache_key = f"rate_limit:{client_ip}:{view_func.__name__}"
            
            # Check rate limit
            requests = cache.get(cache_key, [])
            current_time = time.time()
            
            # Clean old requests
            requests = [req_time for req_time in requests if current_time - req_time < window]
            
            # Check if limit exceeded
            if len(requests) >= limit:
                security_logger.warning(f"Rate limit exceeded for {cache_key}")
                
                return JsonResponse({
                    'error': {
                        'code': 'RATE_LIMIT_EXCEEDED',
                        'message': 'Too many requests. Please try again later.',
                        'retry_after': window
                    }
                }, status=429, headers={'Retry-After': str(window)})
            
            # Record this request
            requests.append(current_time)
            cache.set(cache_key, requests, timeout=window)
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def log_security_event(event_type, severity='INFO'):
    """
    Decorator to log security events
    
    Args:
        event_type: Type of security event
        severity: Event severity (INFO, WARNING, ERROR, CRITICAL)
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            client_ip = _get_client_ip(request)
            user = getattr(request, 'user', None)
            
            # Log security event
            security_logger.log(
                getattr(logging, severity.upper(), logging.INFO),
                f"Security event: {event_type} - User: {user} - IP: {client_ip} - Path: {request.path}"
            )
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def require_authentication(view_func):
    """
    Decorator to require authentication for views
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'error': {
                    'code': 'AUTHENTICATION_REQUIRED',
                    'message': 'Authentication required'
                }
            }, status=401)
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def require_permission(permission):
    """
    Decorator to require specific permission for views
    
    Args:
        permission: Required permission string
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return JsonResponse({
                    'error': {
                        'code': 'AUTHENTICATION_REQUIRED',
                        'message': 'Authentication required'
                    }
                }, status=401)
            
            if not request.user.has_perm(permission):
                security_logger.warning(
                    f"Permission denied: {request.user} attempted to access {request.path} "
                    f"without {permission} permission"
                )
                
                return JsonResponse({
                    'error': {
                        'code': 'PERMISSION_DENIED',
                        'message': 'Insufficient permissions'
                    }
                }, status=403)
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def sanitize_output(view_func):
    """
    Decorator to sanitize output data
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        response = view_func(request, *args, **kwargs)
        
        # Only sanitize JSON responses
        if hasattr(response, 'content') and response.get('Content-Type', '').startswith('application/json'):
            try:
                data = json.loads(response.content.decode('utf-8'))
                sanitized_data = _sanitize_output_data(data)
                response.content = json.dumps(sanitized_data).encode('utf-8')
            except (json.JSONDecodeError, UnicodeDecodeError):
                # If we can't parse the JSON, leave it as is
                pass
        
        return response
    
    return wrapper


# Helper functions

def _get_request_data(request):
    """Extract request data from various sources"""
    request_data = {}
    
    if request.method in ['POST', 'PUT', 'PATCH']:
        content_type = request.META.get('CONTENT_TYPE', '')
        
        if 'application/json' in content_type:
            try:
                if hasattr(request, 'body') and request.body:
                    request_data = json.loads(request.body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise ValidationError('Invalid JSON data')
        
        elif 'application/x-www-form-urlencoded' in content_type:
            request_data = dict(request.POST.items())
        
        elif 'multipart/form-data' in content_type:
            request_data = {k: v for k, v in request.POST.items()}
    
    # Add query parameters
    if request.GET:
        request_data.update(dict(request.GET.items()))
    
    return request_data


def _update_request_data(request, sanitized_data):
    """Update request with sanitized data"""
    if request.method == 'GET':
        request.GET = request.GET.copy()
        for key, value in sanitized_data.items():
            if key in request.GET:
                request.GET[key] = value
    else:
        if hasattr(request, '_body'):
            request._body = json.dumps(sanitized_data).encode('utf-8')
        
        if hasattr(request, 'POST'):
            request.POST = request.POST.copy()
            for key, value in sanitized_data.items():
                if key in request.POST:
                    request.POST[key] = value


def _get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def _sanitize_output_data(data):
    """Sanitize output data to prevent information leakage"""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Remove sensitive keys
            if key.lower() in ['password', 'secret', 'token', 'key', 'private']:
                continue
            
            sanitized[key] = _sanitize_output_data(value)
        return sanitized
    
    elif isinstance(data, list):
        return [_sanitize_output_data(item) for item in data]
    
    elif isinstance(data, str):
        # Remove potential sensitive patterns
        import re
        # Remove potential tokens or keys
        if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', data):  # Base64-like strings
            return '[REDACTED]'
        
        # Remove potential file paths
        if '/' in data and len(data) > 10:
            return '[PATH_REDACTED]'
        
        return data
    
    else:
        return data

def require_organization_access(view_func):
    """
    Decorator to require organization access for views
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'error': {
                    'code': 'AUTHENTICATION_REQUIRED',
                    'message': 'Authentication required'
                }
            }, status=401)
        
        # Check if user has organization access
        if not hasattr(request.user, 'organization') or not request.user.organization:
            return JsonResponse({
                'error': {
                    'code': 'ORGANIZATION_ACCESS_REQUIRED',
                    'message': 'Organization access required'
                }
            }, status=403)
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def require_admin_access(view_func):
    """
    Decorator to require admin access for views
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'error': {
                    'code': 'AUTHENTICATION_REQUIRED',
                    'message': 'Authentication required'
                }
            }, status=401)
        
        # Check if user is admin (superuser or org admin)
        is_admin = (
            request.user.is_superuser or 
            (hasattr(request.user, 'is_org_admin') and request.user.is_org_admin) or
            request.user.is_staff
        )
        
        if not is_admin:
            security_logger.warning(
                f"Admin access denied: {request.user} attempted to access {request.path}"
            )
            
            return JsonResponse({
                'error': {
                    'code': 'ADMIN_ACCESS_REQUIRED',
                    'message': 'Administrator access required'
                }
            }, status=403)
        
        return view_func(request, *args, **kwargs)
    
    return wrapper