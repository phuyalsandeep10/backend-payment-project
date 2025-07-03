"""
Custom middleware to handle Token authentication headers.
Automatically adds 'Token ' prefix if missing from Authorization header.
"""

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
                
        response = self.get_response(request)
        return response 