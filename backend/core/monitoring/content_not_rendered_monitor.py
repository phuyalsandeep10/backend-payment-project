"""
ContentNotRenderedError Monitoring Middleware
Specialized middleware to catch and monitor ContentNotRenderedError occurrences
"""

import logging
import traceback
from typing import Callable
from django.http import HttpRequest, HttpResponse
from django.template.response import ContentNotRenderedError
from django.utils.deprecation import MiddlewareMixin
from .response_processing_monitor import response_processing_monitor
from .error_response import SecureLogger

logger = SecureLogger(__name__)


class ContentNotRenderedMonitorMiddleware:
    """
    Middleware specifically designed to catch ContentNotRenderedError
    and provide detailed monitoring and fallback handling
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
        Process the request and monitor for ContentNotRenderedError
        
        Args:
            request: The HTTP request
            
        Returns:
            HttpResponse: Response with ContentNotRenderedError monitoring
        """
        try:
            response = self.get_response(request)
            return response
            
        except ContentNotRenderedError as cnr_error:
            # Get user info for monitoring
            user_id = None
            organization_id = None
            if hasattr(request, 'user') and request.user.is_authenticated:
                user_id = request.user.id
                if hasattr(request.user, 'organization') and request.user.organization is not None:
                    organization_id = request.user.organization.id
            
            # Record the ContentNotRenderedError
            response_processing_monitor.record_content_not_rendered_error(
                endpoint=request.path,
                method=request.method,
                middleware_name='ContentNotRenderedMonitorMiddleware',
                stack_trace=traceback.format_exc(),
                user_id=user_id,
                organization_id=organization_id
            )
            
            # Log the error with full context
            logger.critical(
                f"ContentNotRenderedError caught in monitor middleware for {request.path}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'user_id': user_id,
                    'organization_id': organization_id,
                    'user_agent': request.META.get('HTTP_USER_AGENT', 'unknown'),
                    'remote_addr': request.META.get('REMOTE_ADDR', 'unknown'),
                    'stack_trace': traceback.format_exc()
                }
            )
            
            # Re-raise the error to let other error handlers deal with it
            raise cnr_error
        
        except Exception as other_error:
            # Log other errors but don't interfere with normal error handling
            logger.debug(
                f"Other exception in ContentNotRenderedMonitorMiddleware: {type(other_error).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'exception_type': type(other_error).__name__,
                    'exception_message': str(other_error)
                }
            )
            
            # Re-raise the error
            raise other_error


class ResponseContentAccessMonitor(MiddlewareMixin):
    """
    Middleware to monitor response content access patterns
    and detect potential ContentNotRenderedError scenarios
    """
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Monitor response content access patterns
        
        Args:
            request: The HTTP request
            response: The HTTP response
            
        Returns:
            HttpResponse: The response (unchanged)
        """
        try:
            # Only monitor API endpoints
            if not request.path.startswith('/api/'):
                return response
            
            response_type = type(response).__name__
            
            # Check if response has content and try to access it safely
            if hasattr(response, 'content'):
                try:
                    # Test content access
                    content_length = len(response.content)
                    
                    # Log successful content access for template responses
                    if hasattr(response, 'is_rendered'):
                        logger.debug(
                            f"Content access successful for {response_type}",
                            extra={
                                'path': request.path,
                                'method': request.method,
                                'response_type': response_type,
                                'is_rendered': getattr(response, 'is_rendered', True),
                                'content_length': content_length,
                                'status_code': response.status_code
                            }
                        )
                    
                except ContentNotRenderedError as cnr_error:
                    # Get user info for monitoring
                    user_id = None
                    organization_id = None
                    if hasattr(request, 'user') and request.user.is_authenticated:
                        user_id = request.user.id
                        if hasattr(request.user, 'organization') and request.user.organization is not None:
                            organization_id = request.user.organization.id
                    
                    # Record the ContentNotRenderedError
                    response_processing_monitor.record_content_not_rendered_error(
                        endpoint=request.path,
                        method=request.method,
                        middleware_name='ResponseContentAccessMonitor',
                        stack_trace=traceback.format_exc(),
                        user_id=user_id,
                        organization_id=organization_id
                    )
                    
                    # Log the error
                    logger.error(
                        f"ContentNotRenderedError during content access monitoring for {request.path}",
                        extra={
                            'path': request.path,
                            'method': request.method,
                            'response_type': response_type,
                            'template_name': getattr(response, 'template_name', 'unknown'),
                            'is_rendered': getattr(response, 'is_rendered', 'unknown')
                        }
                    )
                    
                    # Try to render the response if possible
                    if hasattr(response, 'render') and hasattr(response, 'is_rendered'):
                        if not response.is_rendered:
                            try:
                                logger.info(f"Attempting to render response for {request.path}")
                                response.render()
                                logger.info(f"Successfully rendered response for {request.path}")
                            except Exception as render_error:
                                logger.error(
                                    f"Failed to render response for {request.path}: {str(render_error)}"
                                )
                                # Record the render failure
                                response_processing_monitor.record_response_processing_error(
                                    error_type='RenderFailure',
                                    endpoint=request.path,
                                    method=request.method,
                                    error_message=str(render_error),
                                    stack_trace=traceback.format_exc(),
                                    user_id=user_id,
                                    organization_id=organization_id
                                )
                
                except Exception as other_error:
                    # Log other content access errors
                    logger.warning(
                        f"Content access error for {request.path}: {type(other_error).__name__}",
                        extra={
                            'path': request.path,
                            'method': request.method,
                            'response_type': response_type,
                            'error_message': str(other_error)
                        }
                    )
            
            return response
            
        except Exception as exc:
            # Don't let monitoring errors break the response
            logger.error(
                f"Error in ResponseContentAccessMonitor for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'exception_message': str(exc)
                }
            )
            
            return response


class MiddlewareErrorCatcher:
    """
    Wrapper middleware to catch errors from other middleware and monitor them
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
        Catch and monitor middleware errors
        
        Args:
            request: The HTTP request
            
        Returns:
            HttpResponse: Response with error monitoring
        """
        try:
            return self.get_response(request)
            
        except ContentNotRenderedError as cnr_error:
            # Get user info for monitoring
            user_id = None
            organization_id = None
            if hasattr(request, 'user') and request.user.is_authenticated:
                user_id = request.user.id
                if hasattr(request.user, 'organization') and request.user.organization is not None:
                    organization_id = request.user.organization.id
            
            # Record the ContentNotRenderedError
            response_processing_monitor.record_content_not_rendered_error(
                endpoint=request.path,
                method=request.method,
                middleware_name='MiddlewareErrorCatcher',
                stack_trace=traceback.format_exc(),
                user_id=user_id,
                organization_id=organization_id
            )
            
            # Log the error with middleware stack information
            logger.critical(
                f"ContentNotRenderedError caught in middleware stack for {request.path}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'user_id': user_id,
                    'organization_id': organization_id,
                    'middleware_stack': self._get_middleware_info(),
                    'error_message': str(cnr_error)
                }
            )
            
            # Re-raise to let the global exception handler deal with it
            raise cnr_error
        
        except Exception as other_error:
            # Monitor other middleware errors
            error_type = type(other_error).__name__
            
            # Get user info for monitoring
            user_id = None
            organization_id = None
            if hasattr(request, 'user') and request.user.is_authenticated:
                user_id = request.user.id
                if hasattr(request.user, 'organization') and request.user.organization is not None:
                    organization_id = request.user.organization.id
            
            # Record the error
            response_processing_monitor.record_response_processing_error(
                error_type=error_type,
                endpoint=request.path,
                method=request.method,
                error_message=str(other_error),
                stack_trace=traceback.format_exc(),
                user_id=user_id,
                organization_id=organization_id
            )
            
            # Log the error
            logger.error(
                f"Middleware error caught: {error_type} for {request.path}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'error_type': error_type,
                    'error_message': str(other_error)
                }
            )
            
            # Re-raise the error
            raise other_error
    
    def _get_middleware_info(self) -> str:
        """Get information about the middleware stack"""
        try:
            from django.conf import settings
            middleware = getattr(settings, 'MIDDLEWARE', [])
            return ', '.join([m.split('.')[-1] for m in middleware])
        except Exception:
            return 'unknown'