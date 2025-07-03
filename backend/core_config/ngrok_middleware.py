from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponse

class NgrokCompatibilityMiddleware(MiddlewareMixin):
    """
    Middleware to handle ngrok-specific compatibility issues and enhance CORS support.
    """
    
    def process_request(self, request):
        """Process incoming requests to handle ngrok headers"""
        
        # Handle ngrok-forwarded headers
        if 'HTTP_X_FORWARDED_FOR' in request.META:
            request.META['REMOTE_ADDR'] = request.META['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
        
        if 'HTTP_X_FORWARDED_PROTO' in request.META:
            request.META['wsgi.url_scheme'] = request.META['HTTP_X_FORWARDED_PROTO']
        
        # Store ngrok trace ID for debugging
        if 'HTTP_NGROK_TRACE_ID' in request.META:
            request.ngrok_trace_id = request.META['HTTP_NGROK_TRACE_ID']
        
        return None
    
    def process_response(self, request, response):
        """Process responses to add ngrok-compatible headers"""
        
        # Add comprehensive CORS headers for ngrok compatibility
        origin = request.META.get('HTTP_ORIGIN')
        
        if origin:
            # Check if origin is from ngrok
            if any(domain in origin for domain in ['.ngrok.io', '.ngrok-free.app', '.ngrok.app']):
                response['Access-Control-Allow-Origin'] = origin
                response['Access-Control-Allow-Credentials'] = 'true'
                response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
                response['Access-Control-Allow-Headers'] = ', '.join([
                    'Accept',
                    'Accept-Encoding', 
                    'Authorization',
                    'Content-Type',
                    'DNT',
                    'Origin',
                    'User-Agent',
                    'X-CSRFToken',
                    'X-Requested-With',
                    'Cache-Control',
                    'X-Forwarded-For',
                    'X-Forwarded-Proto',
                    'X-Real-IP',
                    'ngrok-trace-id',
                    'ngrok-skip-browser-warning'
                ])
                response['Access-Control-Max-Age'] = '86400'  # 24 hours
        
        # Handle preflight OPTIONS requests
        if request.method == 'OPTIONS':
            response = HttpResponse()
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
            response['Access-Control-Allow-Headers'] = ', '.join([
                'Accept',
                'Accept-Encoding',
                'Authorization', 
                'Content-Type',
                'DNT',
                'Origin',
                'User-Agent',
                'X-CSRFToken',
                'X-Requested-With',
                'Cache-Control',
                'ngrok-skip-browser-warning'
            ])
            response['Access-Control-Max-Age'] = '86400'
            response['Access-Control-Allow-Credentials'] = 'true'
            response.status_code = 200
        
        # Add security headers that work with ngrok
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'SAMEORIGIN'  # Less restrictive than DENY for development
        
        # Add ngrok trace ID to response for debugging
        if hasattr(request, 'ngrok_trace_id'):
            response['X-Ngrok-Trace-ID'] = request.ngrok_trace_id
        
        return response 