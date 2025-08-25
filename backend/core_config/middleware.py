"""
Security middleware for additional protection measures
"""
import logging
import os
import time
from django.http import HttpResponse
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

security_logger = logging.getLogger('security')

class SecurityHeadersMiddleware:
    """
    Adds security headers to all responses
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Content Security Policy
        import os
        csp_connect = " ".join([
            "'self'",
            os.getenv('FRONTEND_ORIGIN', ''),
            os.getenv('API_ORIGIN', ''),
            os.getenv('WS_ORIGIN', ''),
        ])
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "  # Removed unsafe-inline after frontend consolidation
            "img-src 'self' data: blob: https:; "
            "font-src 'self' https://fonts.gstatic.com; "
            f"connect-src {csp_connect}; "
            "frame-ancestors 'none';"
        )
        
        return response

class RateLimitMiddleware(MiddlewareMixin):
    """
    Additional rate limiting middleware for API endpoints
    """
    
    def process_request(self, request):
        try:
            # Get client IP
            client_ip = self.get_client_ip(request)
            
            # Skip rate limiting for admin and internal requests
            if request.path.startswith('/admin/') or client_ip in ['127.0.0.1', 'localhost']:
                return None
            
            # Different limits for different endpoint types (TEMPORARILY RELAXED FOR TESTING)
            limits = {
                '/api/auth/login/': {'limit': 100, 'window': 300},  # Increased for testing
                '/api/auth/super-admin-login/': {'limit': 100, 'window': 300},  # Increased for testing
                '/api/auth/verify-otp/': {'limit': 100, 'window': 300},  # Increased for testing
                '/api/auth/org-admin/': {'limit': 100, 'window': 300},  # Added for org admin endpoints
                '/api/auth/change-password': {'limit': 100, 'window': 300},  # Added for password change
                'default': {'limit': 1000, 'window': 300}  # Increased default limit
            }
            
            # Find applicable limit
            limit_config = limits.get('default')
            for path, config in limits.items():
                if path != 'default' and request.path.startswith(path):
                    limit_config = config
                    break
            
            # Check rate limit
            cache_key = f"rate_limit:{client_ip}:{request.path}"
            requests = cache.get(cache_key, [])
            
            # Clean old requests
            current_time = time.time()
            requests = [req_time for req_time in requests if current_time - req_time < limit_config['window']]
            
            # Check if limit exceeded
            if len(requests) >= limit_config['limit']:
                security_logger.warning(f"Rate limit exceeded for IP {client_ip} on path {request.path}")
                response = HttpResponse("Rate limit exceeded", status=429)
                response['Retry-After'] = '300'  # Retry after 5 minutes
                return response
            
            # Record this request
            requests.append(current_time)
            cache.set(cache_key, requests, timeout=limit_config['window'])
            
            return None
            
        except Exception as e:
            # Handle cache errors gracefully
            security_logger.error(
                f"Error in RateLimitMiddleware for {request.path}: {type(e).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'RateLimitMiddleware',
                    'exception_type': type(e).__name__,
                    'exception_message': str(e)
                }
            )
            # Allow request to continue if rate limiting fails
            return None
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class SecurityMonitoringMiddleware(MiddlewareMixin):
    """
    Monitor and log suspicious activities
    """
    
    SUSPICIOUS_PATTERNS = [
        'SELECT', 'UNION', 'DROP', 'INSERT', 'UPDATE', 'DELETE',  # SQL injection
        '<script', '</script>', 'javascript:', 'onload=', 'onerror=',  # XSS
        '../', './', '\\..\\', '..\\',  # Path traversal
        'eval(', 'exec(', 'system(', 'shell_exec(',  # Code injection
    ]
    
    def process_request(self, request):
        try:
            # Check for suspicious patterns in request data
            suspicious_found = []
            
            # Check GET parameters
            try:
                for key, value in request.GET.items():
                    for pattern in self.SUSPICIOUS_PATTERNS:
                        if pattern.lower() in str(value).lower():
                            suspicious_found.append(f"GET param {key}: {pattern}")
            except (AttributeError, UnicodeDecodeError) as e:
                security_logger.warning(f"Error checking GET parameters: {str(e)}")
            
            # Check POST data
            try:
                if hasattr(request, 'POST'):
                    for key, value in request.POST.items():
                        for pattern in self.SUSPICIOUS_PATTERNS:
                            if pattern.lower() in str(value).lower():
                                suspicious_found.append(f"POST param {key}: {pattern}")
            except (AttributeError, UnicodeDecodeError) as e:
                security_logger.warning(f"Error checking POST parameters: {str(e)}")
            
            # Check headers for common attack patterns
            try:
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                if any(pattern in user_agent.lower() for pattern in ['sqlmap', 'nikto', 'nmap', 'burp']):
                    suspicious_found.append(f"Suspicious User-Agent: {user_agent}")
            except (AttributeError, UnicodeDecodeError) as e:
                security_logger.warning(f"Error checking User-Agent: {str(e)}")
            
            # Log suspicious activity
            if suspicious_found:
                client_ip = self.get_client_ip(request)
                security_logger.warning(
                    f"Suspicious activity detected from {client_ip} on {request.path}: "
                    f"{', '.join(suspicious_found)}"
                )
            
            return None
            
        except Exception as e:
            # Handle any other errors gracefully
            security_logger.error(
                f"Error in SecurityMonitoringMiddleware for {request.path}: {type(e).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'SecurityMonitoringMiddleware',
                    'exception_type': type(e).__name__,
                    'exception_message': str(e)
                }
            )
            # Allow request to continue
            return None
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Log all requests for monitoring and debugging
    """
    
    def process_request(self, request):
        try:
            # Log request details
            client_ip = self.get_client_ip(request)
            
            # Don't log static files and admin requests to avoid spam
            if not (request.path.startswith('/static/') or 
                    request.path.startswith('/media/') or
                    request.path.startswith('/admin/favicon.ico')):
                
                # Safely get user information
                user_info = 'Anonymous'
                try:
                    if hasattr(request, 'user') and request.user.is_authenticated:
                        user_info = getattr(request.user, 'email', 'Authenticated')
                except AttributeError:
                    user_info = 'Unknown'
                
                security_logger.info(
                    f"Request: {request.method} {request.path} from {client_ip} "
                    f"- User: {user_info}"
                )
            
            return None
            
        except Exception as e:
            # Handle logging errors gracefully
            security_logger.error(
                f"Error in RequestLoggingMiddleware for {request.path}: {type(e).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'RequestLoggingMiddleware',
                    'exception_type': type(e).__name__,
                    'exception_message': str(e)
                }
            )
            # Allow request to continue
            return None
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class CORSPreflightMiddleware:
    """
    Handle CORS preflight requests for shared development access
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            # Handle preflight OPTIONS requests
            if request.method == 'OPTIONS':
                response = HttpResponse()
                
                try:
                    # Get allowed origins from environment
                    frontend_origin = os.getenv('FRONTEND_ORIGIN', 'http://localhost:3000')
                    allowed_origins = [
                        frontend_origin,
                        'http://localhost:3000',
                        'https://localhost:3000'
                    ]
                    
                    # Check origin against allowed list
                    request_origin = request.META.get('HTTP_ORIGIN', '')
                    
                    if settings.DEBUG:
                        # In debug mode, allow all origins
                        response['Access-Control-Allow-Origin'] = '*'
                    elif request_origin in allowed_origins:
                        # In production, only allow specific origins
                        response['Access-Control-Allow-Origin'] = request_origin
                    else:
                        # Deny preflight for unauthorized origins
                        return HttpResponse(status=403)
                    
                    response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
                    response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRFToken'
                    response['Access-Control-Allow-Credentials'] = 'true'
                    response['Access-Control-Max-Age'] = '86400'  # 24 hours
                    
                except Exception as e:
                    security_logger.error(f"Error in CORS preflight handling: {str(e)}")
                    # Return basic CORS response on error
                    response['Access-Control-Allow-Origin'] = '*' if settings.DEBUG else 'http://localhost:3000'
                    response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
                    response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                
                return response
            
            response = self.get_response(request)
            
            try:
                # Add CORS headers to responses
                frontend_origin = os.getenv('FRONTEND_ORIGIN', 'http://localhost:3000')
                request_origin = request.META.get('HTTP_ORIGIN', '')
                
                if settings.DEBUG:
                    # In debug mode, allow all origins
                    response['Access-Control-Allow-Origin'] = '*'
                elif request_origin in [frontend_origin, 'http://localhost:3000', 'https://localhost:3000']:
                    # In production, only allow specific origins
                    response['Access-Control-Allow-Origin'] = request_origin
                
                response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
                response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRFToken'
                response['Access-Control-Allow-Credentials'] = 'true'
                
            except Exception as e:
                security_logger.error(f"Error adding CORS headers: {str(e)}")
                # Continue without CORS headers if there's an error
            
            return response
            
        except Exception as e:
            # Handle any other errors in CORS middleware
            security_logger.error(
                f"Error in CORSPreflightMiddleware for {request.path}: {type(e).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'CORSPreflightMiddleware',
                    'exception_type': type(e).__name__,
                    'exception_message': str(e)
                }
            )
            # Return basic response on critical error
            return self.get_response(request) 