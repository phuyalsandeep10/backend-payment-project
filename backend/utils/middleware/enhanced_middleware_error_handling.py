"""
Enhanced Error Handling for Critical Middleware

This module provides enhanced error handling wrappers for critical Django middleware
to prevent 500 errors and implement graceful degradation when middleware fails.
"""

import logging
import traceback
from typing import Callable, Optional, Any
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.middleware.common import CommonMiddleware
from django.middleware.csrf import CsrfViewMiddleware
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.template.response import ContentNotRenderedError
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from .error_response import SecureLogger

logger = SecureLogger(__name__)

class EnhancedCommonMiddleware(CommonMiddleware):
    """
    Enhanced CommonMiddleware with comprehensive error handling
    Prevents ContentNotRenderedError and other common middleware failures
    """
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Enhanced response processing with error handling
        
        Args:
            request: HTTP request object
            response: HTTP response object
            
        Returns:
            HttpResponse: Processed response with error handling
        """
        try:
            # Call parent process_response with error handling
            return super().process_response(request, response)
            
        except ContentNotRenderedError as exc:
            # Handle ContentNotRenderedError specifically
            logger.warning(
                f"ContentNotRenderedError in CommonMiddleware for {request.path}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                    'middleware': 'CommonMiddleware',
                    'exception_type': 'ContentNotRenderedError'
                }
            )
            
            # Try to render the response if possible
            if hasattr(response, 'render') and callable(response.render):
                try:
                    response.render()
                    logger.info(f"Successfully rendered response in CommonMiddleware for {request.path}")
                    return super().process_response(request, response)
                except Exception as render_exc:
                    logger.error(
                        f"Failed to render response in CommonMiddleware: {type(render_exc).__name__}",
                        extra={
                            'path': request.path,
                            'render_exception': str(render_exc),
                            'middleware': 'CommonMiddleware'
                        }
                    )
            
            # Return the response as-is if rendering fails
            return response
            
        except AttributeError as exc:
            # Handle missing attributes gracefully
            logger.warning(
                f"AttributeError in CommonMiddleware for {request.path}: {str(exc)}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'CommonMiddleware',
                    'exception_type': 'AttributeError'
                }
            )
            
            # Return response without CommonMiddleware processing
            return response
            
        except Exception as exc:
            # Handle any other unexpected errors
            logger.error(
                f"Unexpected error in CommonMiddleware for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'CommonMiddleware',
                    'exception_type': type(exc).__name__,
                    'exception_message': str(exc)
                },
                exc_info=False  # Don't include full traceback in logs
            )
            
            # Return response without CommonMiddleware processing
            return response


class EnhancedCsrfViewMiddleware(CsrfViewMiddleware):
    """
    Enhanced CSRF middleware with better error handling
    """
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Enhanced CSRF request processing with error handling
        
        Args:
            request: HTTP request object
            
        Returns:
            Optional[HttpResponse]: Error response if CSRF validation fails
        """
        try:
            return super().process_request(request)
            
        except Exception as exc:
            logger.error(
                f"Error in CSRF middleware for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'CsrfViewMiddleware',
                    'exception_type': type(exc).__name__,
                    'exception_message': str(exc)
                }
            )
            
            # For API endpoints, return JSON error response
            if request.path.startswith('/api/'):
                return JsonResponse({
                    'error': {
                        'code': 'CSRF_ERROR',
                        'message': 'CSRF validation failed',
                        'details': {
                            'path': request.path,
                            'method': request.method
                        }
                    }
                }, status=status.HTTP_403_FORBIDDEN)
            
            # For non-API endpoints, allow request to continue
            return None
    
    def process_view(self, request: HttpRequest, callback: Callable, callback_args: tuple, callback_kwargs: dict) -> Optional[HttpResponse]:
        """
        Enhanced CSRF view processing with error handling
        
        Args:
            request: HTTP request object
            callback: View callback function
            callback_args: View callback arguments
            callback_kwargs: View callback keyword arguments
            
        Returns:
            Optional[HttpResponse]: Error response if CSRF validation fails
        """
        try:
            return super().process_view(request, callback, callback_args, callback_kwargs)
            
        except Exception as exc:
            logger.error(
                f"Error in CSRF view processing for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'CsrfViewMiddleware',
                    'view_name': getattr(callback, '__name__', 'unknown'),
                    'exception_type': type(exc).__name__,
                    'exception_message': str(exc)
                }
            )
            
            # For API endpoints, return JSON error response
            if request.path.startswith('/api/'):
                return JsonResponse({
                    'error': {
                        'code': 'CSRF_VIEW_ERROR',
                        'message': 'CSRF view processing failed',
                        'details': {
                            'path': request.path,
                            'method': request.method
                        }
                    }
                }, status=status.HTTP_403_FORBIDDEN)
            
            # For non-API endpoints, allow request to continue
            return None


class EnhancedAuthenticationMiddleware(AuthenticationMiddleware):
    """
    Enhanced Authentication middleware with better error handling
    """
    
    def process_request(self, request: HttpRequest) -> None:
        """
        Enhanced authentication processing with error handling
        
        Args:
            request: HTTP request object
        """
        try:
            super().process_request(request)
            
        except Exception as exc:
            logger.error(
                f"Error in Authentication middleware for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'AuthenticationMiddleware',
                    'exception_type': type(exc).__name__,
                    'exception_message': str(exc)
                }
            )
            
            # Set anonymous user if authentication fails
            from django.contrib.auth.models import AnonymousUser
            request.user = AnonymousUser()


class EnhancedSessionMiddleware(SessionMiddleware):
    """
    Enhanced Session middleware with better error handling
    """
    
    def process_request(self, request: HttpRequest) -> None:
        """
        Enhanced session processing with error handling
        
        Args:
            request: HTTP request object
        """
        try:
            super().process_request(request)
            
        except Exception as exc:
            logger.error(
                f"Error in Session middleware for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'SessionMiddleware',
                    'exception_type': type(exc).__name__,
                    'exception_message': str(exc)
                }
            )
            
            # Create empty session if session processing fails
            from django.contrib.sessions.backends.base import SessionBase
            request.session = SessionBase()
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Enhanced session response processing with error handling
        
        Args:
            request: HTTP request object
            response: HTTP response object
            
        Returns:
            HttpResponse: Processed response
        """
        try:
            return super().process_response(request, response)
            
        except Exception as exc:
            logger.error(
                f"Error in Session response processing for {request.path}: {type(exc).__name__}",
                extra={
                    'path': request.path,
                    'method': request.method,
                    'middleware': 'SessionMiddleware',
                    'exception_type': type(exc).__name__,
                    'exception_message': str(exc)
                }
            )
            
            # Return response without session processing
            return response


class MiddlewareErrorHandler(MiddlewareMixin):
    """
    Generic middleware error handler that can wrap any middleware
    """
    
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        """
        Initialize the middleware error handler
        
        Args:
            get_response: Next middleware or view in the chain
        """
        self.get_response = get_response
        super().__init__(get_response)
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        """
        Process request with comprehensive error handling
        
        Args:
            request: HTTP request object
            
        Returns:
            HttpResponse: Processed response
        """
        try:
            response = self.get_response(request)
            return response
            
        except ContentNotRenderedError as exc:
            # Handle ContentNotRenderedError specifically
            return self._handle_content_not_rendered_error(request, exc)
            
        except Exception as exc:
            # Handle any other middleware errors
            return self._handle_generic_middleware_error(request, exc)
    
    def _handle_content_not_rendered_error(self, request: HttpRequest, exc: ContentNotRenderedError) -> HttpResponse:
        """
        Handle ContentNotRenderedError with graceful degradation
        
        Args:
            request: HTTP request object
            exc: ContentNotRenderedError exception
            
        Returns:
            HttpResponse: Fallback response
        """
        logger.warning(
            f"ContentNotRenderedError in middleware chain for {request.path}",
            extra={
                'path': request.path,
                'method': request.method,
                'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'middleware': 'MiddlewareErrorHandler',
                'exception_type': 'ContentNotRenderedError'
            }
        )
        
        # Create fallback JSON response for API endpoints
        if request.path.startswith('/api/'):
            error_data = {
                'error': {
                    'code': 'CONTENT_RENDERING_ERROR',
                    'message': 'Response content could not be rendered',
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
        
        # For non-API endpoints, return basic HTML error
        return HttpResponse(
            content='<html><body><h1>Server Error</h1><p>An error occurred while processing your request.</p></body></html>',
            content_type='text/html',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    def _handle_generic_middleware_error(self, request: HttpRequest, exc: Exception) -> HttpResponse:
        """
        Handle generic middleware errors with graceful degradation
        
        Args:
            request: HTTP request object
            exc: Exception that occurred
            
        Returns:
            HttpResponse: Fallback response
        """
        logger.error(
            f"Middleware error for {request.path}: {type(exc).__name__}",
            extra={
                'path': request.path,
                'method': request.method,
                'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'middleware': 'MiddlewareErrorHandler',
                'exception_type': type(exc).__name__,
                'exception_message': str(exc)
            }
        )
        
        # Create fallback JSON response for API endpoints
        if request.path.startswith('/api/'):
            error_data = {
                'error': {
                    'code': 'MIDDLEWARE_ERROR',
                    'message': 'A middleware error occurred',
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
        
        # For non-API endpoints, return basic HTML error
        return HttpResponse(
            content='<html><body><h1>Server Error</h1><p>An error occurred while processing your request.</p></body></html>',
            content_type='text/html',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class CriticalMiddlewareProtector(MiddlewareMixin):
    """
    Middleware to protect critical middleware from failures
    This should be placed early in the middleware stack
    """
    
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        """
        Initialize the critical middleware protector
        
        Args:
            get_response: Next middleware or view in the chain
        """
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Pre-process request to set up error handling context
        
        Args:
            request: HTTP request object
            
        Returns:
            Optional[HttpResponse]: None to continue processing
        """
        # Add error handling context to request
        request._middleware_error_context = {
            'path': request.path,
            'method': request.method,
            'timestamp': self._get_timestamp(),
            'errors': []
        }
        
        return None
    
    def process_exception(self, request: HttpRequest, exception: Exception) -> Optional[HttpResponse]:
        """
        Handle exceptions from critical middleware
        
        Args:
            request: HTTP request object
            exception: Exception that occurred
            
        Returns:
            Optional[HttpResponse]: Error response if needed
        """
        # Log the middleware exception
        error_context = getattr(request, '_middleware_error_context', {})
        error_context['errors'].append({
            'exception_type': type(exception).__name__,
            'exception_message': str(exception),
            'timestamp': self._get_timestamp()
        })
        
        logger.error(
            f"Critical middleware exception for {request.path}: {type(exception).__name__}",
            extra={
                'path': request.path,
                'method': request.method,
                'middleware': 'CriticalMiddlewareProtector',
                'exception_type': type(exception).__name__,
                'exception_message': str(exception),
                'error_context': error_context
            }
        )
        
        # Handle ContentNotRenderedError specifically
        if isinstance(exception, ContentNotRenderedError):
            return self._create_content_error_response(request, exception)
        
        # For other critical errors, create appropriate response
        return self._create_critical_error_response(request, exception)
    
    def _create_content_error_response(self, request: HttpRequest, exc: ContentNotRenderedError) -> HttpResponse:
        """
        Create response for ContentNotRenderedError
        
        Args:
            request: HTTP request object
            exc: ContentNotRenderedError exception
            
        Returns:
            HttpResponse: Error response
        """
        if request.path.startswith('/api/'):
            error_data = {
                'error': {
                    'code': 'CONTENT_NOT_RENDERED',
                    'message': 'Response content could not be rendered',
                    'details': {
                        'path': request.path,
                        'method': request.method,
                        'timestamp': self._get_timestamp()
                    }
                }
            }
            
            return JsonResponse(error_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return HttpResponse(
            content='Server Error: Content could not be rendered',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    def _create_critical_error_response(self, request: HttpRequest, exc: Exception) -> HttpResponse:
        """
        Create response for critical middleware errors
        
        Args:
            request: HTTP request object
            exc: Exception that occurred
            
        Returns:
            HttpResponse: Error response
        """
        if request.path.startswith('/api/'):
            error_data = {
                'error': {
                    'code': 'CRITICAL_MIDDLEWARE_ERROR',
                    'message': 'A critical system error occurred',
                    'details': {
                        'path': request.path,
                        'method': request.method,
                        'timestamp': self._get_timestamp()
                    }
                }
            }
            
            return JsonResponse(error_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return HttpResponse(
            content='Critical Server Error: Please try again later',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from django.utils import timezone
        return timezone.now().isoformat()