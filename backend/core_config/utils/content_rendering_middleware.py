"""
Content Rendering Middleware
Specifically handles ContentNotRenderedError to prevent 500 errors
"""

import logging
from typing import Callable
from django.http import HttpRequest, HttpResponse
from django.template.response import ContentNotRenderedError
from django.utils.deprecation import MiddlewareMixin
from rest_framework.renderers import JSONRenderer
from rest_framework import status
from core.monitoring.error_handling.error_response import SecureLogger

logger = SecureLogger(__name__)

class ContentNotRenderedErrorMiddleware(MiddlewareMixin):
    """
    Middleware to catch and handle ContentNotRenderedError exceptions
    This prevents 500 errors when responses are not properly rendered
    """
    
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        """
        Initialize the middleware
        
        Args:
            get_response: The next middleware or view in the chain
        """
        self.get_response = get_response
        
    def __call__(self, request: HttpRequest) -> HttpResponse:
        """
        Process the request and handle ContentNotRenderedError
        
        Args:
            request: The HTTP request
            
        Returns:
            HttpResponse: Properly handled response
        """
        try:
            response = self.get_response(request)
            return response
        except ContentNotRenderedError as exc:
            # Handle ContentNotRenderedError specifically
            logger.warning(
                f"ContentNotRenderedError caught for {request.path}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                    'exception_message': str(exc)
                }
            )
            
            # Create a fallback JSON response
            return self._create_fallback_response(request, exc)
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Process response and handle any ContentNotRenderedError during response processing
        
        Args:
            request: The HTTP request
            response: The HTTP response
            
        Returns:
            HttpResponse: Properly handled response
        """
        try:
            # Try to render the response if it needs rendering
            if hasattr(response, 'render') and hasattr(response, 'is_rendered'):
                if not response.is_rendered:
                    try:
                        response.render()
                        logger.debug(f"Successfully rendered response for {request.path}")
                    except Exception as render_exc:
                        logger.error(f"Failed to render response for {request.path}: {str(render_exc)}")
                        return self._create_fallback_response(request, render_exc)
            
            # Test content access to trigger any ContentNotRenderedError early
            if hasattr(response, 'content'):
                try:
                    _ = len(response.content)
                except ContentNotRenderedError as exc:
                    logger.warning(
                        f"ContentNotRenderedError in process_response for {request.path}",
                        extra={
                            'path': request.path,
                            'method': request.method,
                            'exception_message': str(exc)
                        }
                    )
                    return self._create_fallback_response(request, exc)
            
            return response
            
        except ContentNotRenderedError as exc:
            # Handle ContentNotRenderedError in process_response
            logger.warning(
                f"ContentNotRenderedError in process_response for {request.path}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'exception_message': str(exc)
                }
            )
            return self._create_fallback_response(request, exc)
        except Exception as exc:
            # Handle any other exceptions
            logger.error(
                f"Unexpected error in ContentNotRenderedErrorMiddleware for {request.path}: {str(exc)}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'exception_message': str(exc)
                }
            )
            return response
    
    def _create_fallback_response(self, request: HttpRequest, exc: ContentNotRenderedError) -> HttpResponse:
        """
        Create a fallback response when ContentNotRenderedError occurs
        
        Args:
            request: The HTTP request
            exc: The ContentNotRenderedError exception
            
        Returns:
            HttpResponse: Fallback response
        """
        try:
            # Create a simple JSON error response
            error_data = {
                'error': {
                    'code': 'CONTENT_RENDERING_ERROR',
                    'message': 'An error occurred while processing the response',
                    'details': {
                        'path': request.path,
                        'method': request.method
                    }
                }
            }
            
            # Create a simple HttpResponse with JSON content
            response = HttpResponse(
                content=JSONRenderer().render(error_data),
                content_type='application/json',
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            logger.info(
                f"Created fallback response for ContentNotRenderedError on {request.path}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'status_code': response.status_code
                }
            )
            
            return response
            
        except Exception as fallback_exc:
            # If even the fallback fails, create the most basic response
            logger.critical(
                f"Fallback response creation failed for {request.path}: {type(fallback_exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'fallback_exception': str(fallback_exc)
                }
            )
            
            # Create the most basic response possible
            return HttpResponse(
                content='{"error": {"code": "CRITICAL_RENDERING_ERROR", "message": "Critical response rendering error"}}',
                content_type='application/json',
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ResponseContentAccessMiddleware(MiddlewareMixin):
    """
    Middleware to safely handle response content access
    """
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Process response and handle content access safely
        
        Args:
            request: The HTTP request
            response: The HTTP response
            
        Returns:
            HttpResponse: Safely processed response
        """
        try:
            # For API endpoints, ensure content is accessible
            if request.path.startswith('/api/'):
                # Try to access content to trigger any rendering issues early
                try:
                    _ = len(response.content)
                except ContentNotRenderedError:
                    # If content access fails, try to render the response
                    if hasattr(response, 'render') and callable(response.render):
                        try:
                            response.render()
                            logger.info(f"Successfully rendered response for {request.path}")
                        except Exception as render_exc:
                            logger.error(
                                f"Failed to render response for {request.path}: {type(render_exc).__name__}",
                                extra={
                                    'path': request.path,
                                    'method': request.method,
                                    'render_exception': str(render_exc)
                                }
                            )
                            
                            # Create a fallback response
                            return self._create_content_fallback(request, render_exc)
                except Exception as content_exc:
                    logger.error(
                        f"Content access error for {request.path}: {type(content_exc).__name__}",
                        extra={
                            'path': request.path,
                            'method': request.method,
                            'content_exception': str(content_exc)
                        }
                    )
            
            return response
            
        except Exception as exc:
            logger.error(
                f"Error in ResponseContentAccessMiddleware for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'exception_message': str(exc)
                }
            )
            
            return response
    
    def _create_content_fallback(self, request: HttpRequest, exc: Exception) -> HttpResponse:
        """
        Create a fallback response for content access errors
        
        Args:
            request: The HTTP request
            exc: The exception that occurred
            
        Returns:
            HttpResponse: Fallback response
        """
        error_data = {
            'error': {
                'code': 'CONTENT_ACCESS_ERROR',
                'message': 'Response content could not be accessed',
                'details': {
                    'path': request.path,
                    'method': request.method
                }
            }
        }
        
        return HttpResponse(
            content=JSONRenderer().render(error_data),
            content_type='application/json',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )