"""
Response type validation utilities for authentication views.
Ensures all authentication endpoints return proper DRF Response objects.
"""

import logging
from functools import wraps
from django.http import HttpResponse
from django.template.response import TemplateResponse
from rest_framework.response import Response
from rest_framework import status

# Security logger
security_logger = logging.getLogger('security')

# Import enhanced logging
from .response_validation_logger import log_response_validation_event

def validate_response_type(view_func):
    """
    Decorator to validate that API views return appropriate DRF Response objects.
    Converts TemplateResponse objects to DRF Response objects to prevent ContentNotRenderedError.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        try:
            response = view_func(*args, **kwargs)
            
            # Check if response is a TemplateResponse (which can cause ContentNotRenderedError)
            if isinstance(response, TemplateResponse):
                template_name = getattr(response, 'template_name', 'unknown')
                log_response_validation_event(
                    'template_conversion', 
                    view_func.__name__, 
                    template_name=template_name
                )
                
                # Render the template response to get the content
                response.render()
                
                # Convert to DRF Response
                return Response(
                    data={'error': 'Template response converted to API response'},
                    status=response.status_code,
                    content_type='application/json'
                )
            
            # Check if response is a basic HttpResponse (should be DRF Response for API endpoints)
            elif isinstance(response, HttpResponse) and not isinstance(response, Response):
                # Allow JsonResponse for specific cases like health checks
                from django.http import JsonResponse
                if not isinstance(response, JsonResponse):
                    security_logger.warning(
                        f"HttpResponse detected in {view_func.__name__}. Should use DRF Response for API endpoints."
                    )
            
            # Log successful response validation
            log_response_validation_event(
                'validation_success',
                view_func.__name__,
                response_type=type(response).__name__
            )
            
            return response
            
        except Exception as e:
            log_response_validation_event(
                'validation_error',
                view_func.__name__,
                error=e
            )
            
            # Return a safe DRF Response in case of validation errors
            return Response(
                data={'error': 'Internal server error during response processing'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    return wrapper

def ensure_drf_response(view_func):
    """
    Decorator specifically for authentication views to ensure DRF Response objects.
    More strict than validate_response_type - converts any non-DRF response.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        try:
            response = view_func(*args, **kwargs)
            
            # If it's already a DRF Response, return as-is
            if isinstance(response, Response):
                return response
            
            # Handle TemplateResponse
            if isinstance(response, TemplateResponse):
                security_logger.warning(
                    f"TemplateResponse in authentication view {view_func.__name__}. Converting to DRF Response."
                )
                
                # Render the template to get content
                response.render()
                
                # Try to parse as JSON if possible, otherwise return as text
                try:
                    import json
                    content = json.loads(response.content.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    content = {'message': response.content.decode('utf-8', errors='ignore')}
                
                return Response(
                    data=content,
                    status=response.status_code
                )
            
            # Handle JsonResponse (convert to DRF Response for consistency)
            from django.http import JsonResponse
            if isinstance(response, JsonResponse):
                try:
                    import json
                    content = json.loads(response.content.decode('utf-8'))
                    return Response(
                        data=content,
                        status=response.status_code
                    )
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return Response(
                        data={'message': 'Response conversion error'},
                        status=response.status_code
                    )
            
            # Handle other HttpResponse types
            if isinstance(response, HttpResponse):
                security_logger.warning(
                    f"HttpResponse in authentication view {view_func.__name__}. Converting to DRF Response."
                )
                
                try:
                    content = response.content.decode('utf-8')
                    # Try to parse as JSON
                    import json
                    data = json.loads(content)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    data = {'message': content}
                
                return Response(
                    data=data,
                    status=response.status_code
                )
            
            # If it's not an HTTP response at all, wrap it
            security_logger.warning(
                f"Non-HTTP response in authentication view {view_func.__name__}: {type(response)}. Wrapping in DRF Response."
            )
            
            return Response(
                data={'result': str(response)},
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            security_logger.error(
                f"Error in DRF response conversion for {view_func.__name__}: {str(e)}"
            )
            
            return Response(
                data={'error': 'Authentication response processing error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    return wrapper

def log_response_type(view_func):
    """
    Decorator to log response types for debugging purposes.
    Helps identify views that might be returning unexpected response types.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        response = view_func(*args, **kwargs)
        
        security_logger.debug(
            f"Response type for {view_func.__name__}: {type(response).__name__}"
        )
        
        # Log additional details for problematic response types
        if isinstance(response, TemplateResponse):
            security_logger.warning(
                f"TemplateResponse detected in {view_func.__name__} - "
                f"template: {getattr(response, 'template_name', 'unknown')}"
            )
        
        return response
    
    return wrapper