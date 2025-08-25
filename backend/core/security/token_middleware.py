"""
Custom middleware to handle Token authentication headers.
Automatically adds 'Token ' prefix if missing from Authorization header.
"""
import logging

logger = logging.getLogger(__name__)

class TokenAuthMiddleware:
    """
    Middleware to automatically add 'Token ' prefix to Authorization headers
    when they contain raw token values without the prefix.
    
    This fixes the Swagger UI issue where curl commands are generated
    without the required 'Token ' prefix.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Process the Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        request_path = request.path
        
        # Log authentication status for dashboard endpoints
        if '/api/dashboard/' in request_path or '/api/verifier/' in request_path:
            if auth_header:
                if auth_header.startswith('Token '):
                    logger.debug(f"🔑 Valid token auth header for {request_path}")
                else:
                    logger.debug(f"🔑 Auth header without Token prefix for {request_path}: {auth_header[:10]}...")
            else:
                logger.warning(f"🔑 NO authorization header for {request_path} - will result in anonymous user")
        
        if auth_header:
            # Check if it's a raw token (40 characters, alphanumeric)
            # and doesn't already have a prefix
            if (len(auth_header) == 40 and 
                auth_header.isalnum() and 
                not auth_header.startswith('Token ') and
                not auth_header.startswith('Bearer ') and
                not auth_header.startswith('Basic ')):
                
                # Add the Token prefix
                request.META['HTTP_AUTHORIZATION'] = f'Token {auth_header}'
                logger.debug(f"🔑 Added Token prefix to raw token for {request_path}")
                
        response = self.get_response(request)
        return response 