"""
Security middleware for additional protection measures
"""
import logging
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
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        
        return response

class RateLimitMiddleware(MiddlewareMixin):
    """
    Additional rate limiting middleware for API endpoints
    """
    
    def process_request(self, request):
        # Get client IP
        client_ip = self.get_client_ip(request)
        
        # Skip rate limiting for admin and internal requests
        if request.path.startswith('/admin/') or client_ip in ['127.0.0.1', 'localhost']:
            return None
        
        # Different limits for different endpoint types
        limits = {
            '/api/auth/login/': {'limit': 10, 'window': 300},  # 10 per 5 minutes
            '/api/auth/super-admin-login/': {'limit': 5, 'window': 900},  # 5 per 15 minutes
            '/api/auth/verify-otp/': {'limit': 5, 'window': 300},  # 5 per 5 minutes
            'default': {'limit': 100, 'window': 300}  # 100 per 5 minutes
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
        # Check for suspicious patterns in request data
        suspicious_found = []
        
        # Check GET parameters
        for key, value in request.GET.items():
            for pattern in self.SUSPICIOUS_PATTERNS:
                if pattern.lower() in str(value).lower():
                    suspicious_found.append(f"GET param {key}: {pattern}")
        
        # Check POST data
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                for pattern in self.SUSPICIOUS_PATTERNS:
                    if pattern.lower() in str(value).lower():
                        suspicious_found.append(f"POST param {key}: {pattern}")
        
        # Check headers for common attack patterns
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        if any(pattern in user_agent.lower() for pattern in ['sqlmap', 'nikto', 'nmap', 'burp']):
            suspicious_found.append(f"Suspicious User-Agent: {user_agent}")
        
        # Log suspicious activity
        if suspicious_found:
            client_ip = self.get_client_ip(request)
            security_logger.warning(
                f"Suspicious activity detected from {client_ip} on {request.path}: "
                f"{', '.join(suspicious_found)}"
            )
        
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
        # Log request details
        client_ip = self.get_client_ip(request)
        
        # Don't log static files and admin requests to avoid spam
        if not (request.path.startswith('/static/') or 
                request.path.startswith('/media/') or
                request.path.startswith('/admin/favicon.ico')):
            
            security_logger.info(
                f"Request: {request.method} {request.path} from {client_ip} "
                f"- User: {getattr(request.user, 'email', 'Anonymous')}"
            )
        
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
        # Handle preflight OPTIONS requests
        if request.method == 'OPTIONS':
            response = HttpResponse()
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRFToken'
            response['Access-Control-Allow-Credentials'] = 'true'
            response['Access-Control-Max-Age'] = '86400'  # 24 hours
            return response
        
        response = self.get_response(request)
        
        # Add CORS headers to all responses in debug mode
        if settings.DEBUG:
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-CSRFToken'
            response['Access-Control-Allow-Credentials'] = 'true'
        
        return response 