"""
Response Rendering Middleware
Handles template response rendering before other middleware processes them
to prevent ContentNotRenderedError
"""

import logging
import time
import traceback
from typing import Any, Callable
from django.http import HttpRequest, HttpResponse
from django.template.response import TemplateResponse
from django.utils.deprecation import MiddlewareMixin
from rest_framework.response import Response as DRFResponse
from rest_framework.renderers import JSONRenderer
from rest_framework import status
from core.monitoring.error_handling.error_response import SecureLogger
from core.monitoring.response_processing_monitor import response_processing_monitor

logger = SecureLogger(__name__)

class ResponseRenderingMiddleware:
    """
    Middleware to ensure all template responses are rendered before 
    other middleware processes them, preventing ContentNotRenderedError
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
        Process the request and ensure response is properly rendered
        
        Args:
            request: The HTTP request
            
        Returns:
            HttpResponse: Properly rendered response
        """
        # Process the request through the view and other middleware
        response = self.get_response(request)
        
        # Process the response to ensure it's rendered
        return self.process_response(request, response)
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Process the response to ensure template responses are rendered
        
        Args:
            request: The HTTP request
            response: The HTTP response
            
        Returns:
            HttpResponse: Properly rendered response
        """
        start_time = time.time()
        response_type = type(response).__name__
        
        # Get user info for monitoring
        user_id = None
        organization_id = None
        if hasattr(request, 'user') and request.user.is_authenticated:
            user_id = request.user.id
            if hasattr(request.user, 'organization') and request.user.organization is not None:
                organization_id = request.user.organization.id
        
        try:
            # Check if this response has rendering capabilities and needs rendering
            if hasattr(response, 'render') and hasattr(response, 'is_rendered'):
                if not response.is_rendered:
                    render_start = time.time()
                    template_name = getattr(response, 'template_name', 'unknown')
                    
                    logger.info(
                        f"Rendering response for {request.path}",
                        extra={
                            'path': request.path,
                            'method': request.method,
                            'response_type': response_type,
                            'template_name': template_name
                        }
                    )
                    
                    # Special handling for DRF Response objects
                    if hasattr(response, 'accepted_renderer') and not response.accepted_renderer:
                        # DRF Response without renderer - skip rendering to avoid errors
                        logger.warning(
                            f"DRF Response without accepted_renderer for {request.path}, skipping render",
                            extra={
                                'path': request.path,
                                'response_type': response_type
                            }
                        )
                        render_success = True
                        render_time = time.time() - render_start
                    else:
                        # Render the response
                        try:
                            response.render()
                            render_time = time.time() - render_start
                            render_success = True
                            
                            logger.debug(
                                f"Successfully rendered response for {request.path}",
                                extra={
                                    'path': request.path,
                                    'status_code': response.status_code,
                                    'content_length': len(response.content) if hasattr(response, 'content') else 0,
                                    'render_time': render_time
                                }
                            )
                        except Exception as render_exc:
                            render_time = time.time() - render_start
                            render_success = False
                            logger.error(f"Template render failed: {template_name} - {str(render_exc)}")
                            raise render_exc
                    
                    # Record template rendering metrics
                    if isinstance(response, TemplateResponse):
                        context_size = len(str(response.context_data)) if hasattr(response, 'context_data') and response.context_data else None
                        response_processing_monitor.record_template_render(
                            template_name=template_name,
                            render_time=render_time,
                            success=render_success,
                            error_message=None if render_success else "Render failed",
                            context_size=context_size
                        )
            
            # For responses without render capability, validate content access safely
            elif hasattr(response, 'content'):
                try:
                    # Try to access content to ensure it's accessible
                    _ = response.content
                except Exception as content_exc:
                    # Check if this is a ContentNotRenderedError
                    if type(content_exc).__name__ == 'ContentNotRenderedError':
                        # Record the ContentNotRenderedError
                        response_processing_monitor.record_content_not_rendered_error(
                            endpoint=request.path,
                            method=request.method,
                            middleware_name='ResponseRenderingMiddleware',
                            stack_trace=traceback.format_exc(),
                            user_id=user_id,
                            organization_id=organization_id
                        )
                    
                    # If content access fails and response has render method, try to render
                    if hasattr(response, 'render') and callable(response.render):
                        logger.info(f"Attempting to render response with render() method for {request.path}")
                        response.render()
                        # Try content access again after rendering
                        _ = response.content
                    else:
                        # Re-raise the original exception if we can't render
                        raise content_exc
            
            # Record response type metrics
            total_time = time.time() - start_time
            response_processing_monitor.record_response_type(
                response_type=response_type,
                endpoint=request.path,
                method=request.method,
                status_code=getattr(response, 'status_code', 200),
                render_time=total_time,
                user_id=user_id,
                organization_id=organization_id
            )
                
            return response
            
        except Exception as exc:
            # Record the error
            error_type = type(exc).__name__
            if error_type == 'ContentNotRenderedError':
                response_processing_monitor.record_content_not_rendered_error(
                    endpoint=request.path,
                    method=request.method,
                    middleware_name='ResponseRenderingMiddleware',
                    stack_trace=traceback.format_exc(),
                    user_id=user_id,
                    organization_id=organization_id
                )
            else:
                response_processing_monitor.record_response_processing_error(
                    error_type=error_type,
                    endpoint=request.path,
                    method=request.method,
                    error_message=str(exc),
                    stack_trace=traceback.format_exc(),
                    user_id=user_id,
                    organization_id=organization_id
                )
            
            # Log the error and attempt to create a fallback response
            logger.error(
                f"Error in ResponseRenderingMiddleware for {request.path}: {error_type}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'response_type': response_type,
                    'exception_type': error_type,
                    'exception_message': str(exc)
                },
                exc_info=True
            )
            
            # Create a fallback response
            return self._create_fallback_response(request, exc)
    
    def _create_fallback_response(self, request: HttpRequest, original_exception: Exception) -> HttpResponse:
        """
        Create a fallback response when template rendering fails
        
        Args:
            request: The HTTP request
            original_exception: The original exception that occurred
            
        Returns:
            HttpResponse: Fallback response
        """
        try:
            # Try to create a DRF Response as fallback
            error_data = {
                'error': {
                    'code': 'RESPONSE_RENDERING_ERROR',
                    'message': 'An error occurred while processing the response',
                    'timestamp': None  # Will be set by StandardErrorResponse if used
                }
            }
            
            # Create a simple JSON response
            fallback_response = HttpResponse(
                content=JSONRenderer().render(error_data),
                content_type='application/json',
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            logger.info(
                f"Created fallback response for {request.path}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'fallback_status': fallback_response.status_code
                }
            )
            
            return fallback_response
            
        except Exception as fallback_exc:
            # If even the fallback fails, create a minimal response
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
                content='{"error": {"code": "CRITICAL_ERROR", "message": "A critical error occurred"}}',
                content_type='application/json',
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ResponseTypeValidationMiddleware(MiddlewareMixin):
    """
    Middleware to validate and log response types for monitoring
    """
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Validate and log response types
        
        Args:
            request: The HTTP request
            response: The HTTP response
            
        Returns:
            HttpResponse: The response (unchanged)
        """
        try:
            # Log response type information for API endpoints
            if request.path.startswith('/api/'):
                response_type = type(response).__name__
                is_rendered = True
                
                # Check if it's a template response and if it's rendered
                if isinstance(response, TemplateResponse):
                    is_rendered = response.is_rendered
                
                # Get user info for monitoring
                user_id = None
                organization_id = None
                if hasattr(request, 'user') and request.user.is_authenticated:
                    user_id = request.user.id
                    if hasattr(request.user, 'organization') and request.user.organization is not None:
                        organization_id = request.user.organization.id
                
                # Log response type information
                logger.debug(
                    f"Response type validation for {request.path}",
                    extra={
                        'path': request.path,
                        'method': request.method,
                        'response_type': response_type,
                        'status_code': response.status_code,
                        'is_rendered': is_rendered,
                        'content_type': response.get('Content-Type', 'unknown')
                    }
                )
                
                # Record response type for monitoring (if not already recorded)
                response_processing_monitor.record_response_type(
                    response_type=response_type,
                    endpoint=request.path,
                    method=request.method,
                    status_code=response.status_code,
                    render_time=None,  # No render time in validation middleware
                    user_id=user_id,
                    organization_id=organization_id
                )
                
                # Warn about unrendered template responses
                if isinstance(response, TemplateResponse) and not is_rendered:
                    logger.warning(
                        f"Unrendered TemplateResponse detected for API endpoint {request.path}",
                        extra={
                            'path': request.path,
                            'method': request.method,
                            'response_type': response_type,
                            'template_name': getattr(response, 'template_name', 'unknown')
                        }
                    )
                    
                    # Record this as a potential issue
                    response_processing_monitor.record_response_processing_error(
                        error_type='UnrenderedTemplateResponse',
                        endpoint=request.path,
                        method=request.method,
                        error_message=f"Unrendered TemplateResponse for API endpoint: {getattr(response, 'template_name', 'unknown')}",
                        stack_trace='',
                        user_id=user_id,
                        organization_id=organization_id
                    )
            
            return response
            
        except Exception as exc:
            # Don't let validation errors break the response
            logger.error(
                f"Error in ResponseTypeValidationMiddleware for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'exception_message': str(exc)
                }
            )
            
            return response


class ContentAccessProtectionMiddleware:
    """
    Middleware to protect against premature content access
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
        Process the request and protect against content access issues
        
        Args:
            request: The HTTP request
            
        Returns:
            HttpResponse: Protected response
        """
        response = self.get_response(request)
        
        # Ensure response content is accessible
        try:
            # Test content access
            if hasattr(response, 'content'):
                _ = len(response.content)
                
        except Exception as exc:
            logger.error(
                f"Content access error for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'response_type': type(response).__name__,
                    'exception_message': str(exc)
                }
            )
            
            # If content access fails, try to render if it's a template response
            if isinstance(response, TemplateResponse) and not response.is_rendered:
                try:
                    response.render()
                    logger.info(f"Successfully rendered response after content access error for {request.path}")
                except Exception as render_exc:
                    logger.error(
                        f"Failed to render response after content access error for {request.path}: {type(render_exc).__name__}",
                        extra={'render_exception': str(render_exc)}
                    )
        
        return response