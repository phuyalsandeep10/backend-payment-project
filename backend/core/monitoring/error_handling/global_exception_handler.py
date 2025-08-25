"""
Global Exception Handler for Django REST Framework
Provides consistent error handling across all API endpoints
"""

from typing import Optional, Dict, Any
from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError, PermissionDenied
from django.http import Http404, HttpResponse
from django.template.response import ContentNotRenderedError
from django.utils import timezone
from rest_framework import status
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer
from rest_framework.exceptions import (
    APIException, AuthenticationFailed, NotAuthenticated,
    PermissionDenied as DRFPermissionDenied, NotFound,
    ValidationError as DRFValidationError, Throttled,
    ParseError, UnsupportedMediaType, MethodNotAllowed
)
from .error_response import StandardErrorResponse, SecureLogger

logger = SecureLogger(__name__)


def validate_response_type(response, context=None):
    """
    Validate that a response is a properly rendered DRF Response object
    This helps prevent ContentNotRenderedError issues
    """
    from django.template.response import TemplateResponse
    
    if response is None:
        return None
    
    # Log response type for debugging
    logger.debug(f"Validating response type: {type(response).__name__}")
    
    # Handle TemplateResponse - these cause ContentNotRenderedError
    if isinstance(response, TemplateResponse):
        logger.warning("TemplateResponse detected - converting to DRF Response")
        return _ensure_response_rendered(response)
    
    # Handle DRF Response
    if isinstance(response, Response):
        return _ensure_response_rendered(response)
    
    # Handle other HttpResponse types
    if isinstance(response, HttpResponse):
        logger.info("HttpResponse detected - converting to DRF Response")
        return _ensure_response_rendered(response)
    
    # Unknown response type
    logger.warning(f"Unknown response type: {type(response)}")
    return _ensure_response_rendered(response)

def _ensure_response_rendered(response):
    """
    Ensure that a DRF Response is properly set up for rendering and prevent ContentNotRenderedError
    """
    from django.template.response import TemplateResponse
    from django.http import HttpResponse
    
    # Handle TemplateResponse objects by converting them to DRF Response
    if isinstance(response, TemplateResponse):
        logger.warning("Converting TemplateResponse to DRF Response to prevent ContentNotRenderedError")
        try:
            # Render the template response first
            response.render()
            # Convert to DRF Response with the rendered content
            error_response = StandardErrorResponse(
                error_code='TEMPLATE_RESPONSE_CONVERTED',
                message="Template response converted to API response",
                status_code=response.status_code if hasattr(response, 'status_code') else 500
            )
            return error_response.to_response()
        except Exception as template_exc:
            logger.error(f"Failed to render TemplateResponse: {template_exc}")
            # Create fallback response
            error_response = StandardErrorResponse.server_error(
                message="Template rendering failed - using fallback response"
            )
            return error_response.to_response()
    
    # Handle DRF Response objects
    if isinstance(response, Response):
        # Set up renderer if not already set
        if not hasattr(response, 'accepted_renderer') or not response.accepted_renderer:
            response.accepted_renderer = JSONRenderer()
            response.accepted_media_type = 'application/json'
            response.renderer_context = {}
        
        # Render the response if not already rendered
        if hasattr(response, 'is_rendered') and not response.is_rendered:
            try:
                response.render()
            except Exception as render_exc:
                logger.error(f"Failed to render DRF response: {render_exc}")
                # Create a simple fallback response
                error_response = StandardErrorResponse.server_error(
                    message="Response rendering failed - using fallback"
                )
                return error_response.to_response()
        
        return response
    
    # Handle HttpResponse objects - convert to DRF Response for consistency
    if isinstance(response, HttpResponse):
        try:
            # Try to parse content as JSON if it's JSON content type
            if response.get('Content-Type', '').startswith('application/json'):
                import json
                content = response.content.decode('utf-8')
                data = json.loads(content)
                return Response(data, status=response.status_code)
            else:
                # Convert non-JSON HttpResponse to standardized error response
                error_response = StandardErrorResponse(
                    error_code='HTTP_RESPONSE_CONVERTED',
                    message="Non-API response converted to API format",
                    status_code=response.status_code
                )
                return error_response.to_response()
        except Exception as convert_exc:
            logger.error(f"Failed to convert HttpResponse: {convert_exc}")
            error_response = StandardErrorResponse.server_error(
                message="Response conversion failed - using fallback"
            )
            return error_response.to_response()
    
    # If it's not a recognized response type, create a standardized response
    logger.warning(f"Unknown response type: {type(response)}, creating standardized response")
    error_response = StandardErrorResponse.server_error(
        message="Unknown response type - using standardized format"
    )
    return error_response.to_response()

def global_exception_handler(exc, context):
    """
    Global exception handler that returns standardized error responses
    
    Args:
        exc: The exception instance
        context: Context dictionary containing view, request, etc.
    
    Returns:
        Response: Standardized error response
    """
    # Get request from context
    request = context.get('request')
    request_id = getattr(request, 'request_id', None) if request else None
    
    # Get view information for logging
    view = context.get('view')
    view_name = getattr(view, '__class__.__name__', 'Unknown') if view else 'Unknown'
    
    # Log the exception
    logger.error(
        f"Exception in {view_name}: {type(exc).__name__}",
        extra={
            'request_id': request_id,
            'view_name': view_name,
            'path': request.path if request else 'unknown',
            'method': request.method if request else 'unknown',
            'user_id': getattr(request.user, 'id', None) if request and hasattr(request, 'user') else None,
            'exception_type': type(exc).__name__,
            'exception_message': str(exc)
        },
        exc_info=settings.DEBUG
    )
    
    # Handle ContentNotRenderedError specifically - this is the main issue causing 500 errors
    if isinstance(exc, ContentNotRenderedError):
        logger.error(
            f"ContentNotRenderedError in {view_name} - this indicates a template response was not rendered before middleware accessed it",
            extra={
                'request_id': request_id,
                'view_name': view_name,
                'path': request.path if request else 'unknown',
                'method': request.method if request else 'unknown',
                'error_details': str(exc)
            }
        )
        
        # Create a properly rendered DRF response immediately
        error_response = StandardErrorResponse(
            error_code='CONTENT_RENDERING_ERROR',
            message="Response content was not rendered before access - this has been fixed",
            details={
                'technical_info': 'Template response was accessed before rendering',
                'resolution': 'Converted to properly rendered API response'
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            request_id=request_id
        )
        
        # Return the response directly - it's already properly set up for rendering
        response = error_response.to_response()
        # Force render immediately to prevent any further ContentNotRenderedError
        response.render()
        return response
    
    # Handle specific exception types
    error_response = None
    
    if isinstance(exc, NotAuthenticated):
        error_response = StandardErrorResponse.authentication_error(
            message="Authentication credentials were not provided",
            request_id=request_id
        )
    
    elif isinstance(exc, AuthenticationFailed):
        error_response = StandardErrorResponse.authentication_error(
            message="Invalid authentication credentials",
            request_id=request_id
        )
    
    elif isinstance(exc, (PermissionDenied, DRFPermissionDenied)):
        error_response = StandardErrorResponse.permission_error(
            message="You do not have permission to perform this action",
            request_id=request_id
        )
        
        # Log permission denied event
        if request:
            logger.log_permission_denied(
                user_id=getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                resource=request.path,
                action=request.method,
                ip_address=_get_client_ip(request)
            )
    
    elif isinstance(exc, (NotFound, Http404)):
        error_response = StandardErrorResponse.not_found_error(
            message="The requested resource was not found",
            request_id=request_id
        )
    
    elif isinstance(exc, (DjangoValidationError, DRFValidationError)):
        details = _extract_validation_details(exc)
        # Get a more specific message from the validation error
        validation_message = "Validation failed"
        if details:
            if isinstance(details, dict):
                # Try to get a specific error message
                if 'message' in details:
                    validation_message = details['message']
                elif 'errors' in details and details['errors']:
                    first_error = details['errors'][0] if isinstance(details['errors'], list) else details['errors']
                    validation_message = str(first_error)
                # Handle nested payment validation errors
                elif 'payments' in details and details['payments']:
                    payments_errors = details['payments']
                    if isinstance(payments_errors, list) and len(payments_errors) > 0:
                        payment_error = payments_errors[0]
                        if isinstance(payment_error, dict):
                            # Get first error from first payment
                            for field, error_list in payment_error.items():
                                if error_list:
                                    first_error = error_list[0] if isinstance(error_list, list) else error_list
                                    validation_message = str(first_error)
                                    break
                elif len(details) > 0:
                    # Get first field error
                    first_key = list(details.keys())[0]
                    first_error = details[first_key]
                    if isinstance(first_error, list) and first_error:
                        validation_message = f"{first_key}: {first_error[0]}"
                    else:
                        validation_message = f"{first_key}: {first_error}"
        
        error_response = StandardErrorResponse.validation_error(
            message=validation_message,
            details=details,
            request_id=request_id
        )
    
    elif isinstance(exc, Throttled):
        retry_after = getattr(exc, 'wait', None)
        error_response = StandardErrorResponse.rate_limit_error(
            message="Rate limit exceeded. Please try again later.",
            retry_after=retry_after,
            request_id=request_id
        )
    
    elif isinstance(exc, ParseError):
        error_response = StandardErrorResponse(
            error_code='PARSE_ERROR',
            message="Malformed request data",
            status_code=status.HTTP_400_BAD_REQUEST,
            request_id=request_id
        )
    
    elif isinstance(exc, UnsupportedMediaType):
        error_response = StandardErrorResponse(
            error_code='UNSUPPORTED_MEDIA_TYPE',
            message="Unsupported media type in request",
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            request_id=request_id
        )
    
    elif isinstance(exc, MethodNotAllowed):
        # Fix: Handle ErrorDetail object properly
        detail = getattr(exc, 'detail', None)
        allowed_methods = []
        
        # Extract allowed methods safely
        if hasattr(detail, 'get') and callable(detail.get):
            allowed_methods = detail.get('allowed_methods', [])
        elif hasattr(exc, 'allowed_methods'):
            allowed_methods = exc.allowed_methods
        
        details = {'allowed_methods': allowed_methods} if allowed_methods else {}
        
        error_response = StandardErrorResponse(
            error_code='METHOD_NOT_ALLOWED',
            message="Method not allowed for this endpoint",
            details=details,
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            request_id=request_id
        )
    
    elif isinstance(exc, APIException):
        # Generic API exception handling
        error_code = getattr(exc, 'default_code', 'API_ERROR').upper()
        status_code = getattr(exc, 'status_code', status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        error_response = StandardErrorResponse(
            error_code=error_code,
            message=str(exc.detail) if hasattr(exc, 'detail') else str(exc),
            status_code=status_code,
            request_id=request_id
        )
    
    else:
        # Handle non-API exceptions
        error_response = _handle_non_api_exception(exc, request_id, view_name)
    
    # If we created a standardized error response, return it
    if error_response:
        response = error_response.to_response()
        # Validate and ensure proper rendering
        return validate_response_type(response, context)
    
    # Fall back to DRF's default exception handler
    try:
        response = drf_exception_handler(exc, context)
    except Exception as drf_exc:
        logger.error(f"DRF exception handler failed: {drf_exc}")
        # Create fallback response if DRF handler fails
        error_response = StandardErrorResponse.server_error(
            message="Exception handler failed - using emergency fallback",
            request_id=request_id
        )
        response = error_response.to_response()
        response.render()
        return response
    
    if response is not None:
        # Ensure DRF response is properly rendered and prevent any template response issues
        try:
            response = _ensure_response_rendered(response)
            
            # Additional safety check - if response is still not a DRF Response, convert it
            if not isinstance(response, Response):
                logger.warning(f"Non-DRF response returned from handler: {type(response)}")
                error_response = StandardErrorResponse(
                    error_code='RESPONSE_TYPE_ERROR',
                    message="Invalid response type converted to API format",
                    status_code=getattr(response, 'status_code', 500),
                    request_id=request_id
                )
                response = error_response.to_response()
                response.render()
            
            return response
            
        except Exception as render_exc:
            logger.error(f"Failed to ensure response rendering: {render_exc}")
            # Emergency fallback - create a completely new response
            error_response = StandardErrorResponse.server_error(
                message="Response processing failed - using emergency fallback",
                request_id=request_id
            )
            response = error_response.to_response()
            response.render()
            return response
    
    # If no response was generated, create a generic server error
    error_response = StandardErrorResponse.server_error(
        message="An unexpected error occurred. Please try again later.",
        request_id=request_id
    )
    
    # Log unexpected errors as critical
    logger.critical(
        f"Unhandled exception in {view_name}: {type(exc).__name__}",
        extra={
            'request_id': request_id,
            'view_name': view_name,
            'exception_message': str(exc),
            'exception_type': type(exc).__name__
        },
        exc_info=settings.DEBUG
    )
    
    # Create final response with immediate rendering to prevent any ContentNotRenderedError
    try:
        response = error_response.to_response()
        response.render()  # Force immediate rendering
        return response
    except Exception as final_exc:
        logger.critical(f"Final response creation failed: {final_exc}")
        # Absolute last resort - create minimal HttpResponse
        from django.http import JsonResponse
        return JsonResponse(
            {
                'error': {
                    'code': 'CRITICAL_ERROR',
                    'message': 'Critical system error - emergency response',
                    'request_id': request_id,
                    'timestamp': timezone.now().isoformat()
                }
            },
            status=500
        )


def _extract_validation_details(exc) -> Dict[str, Any]:
    """
    Extract validation error details from exception
    """
    details = {}
    
    if hasattr(exc, 'detail'):
        if isinstance(exc.detail, dict):
            details = exc.detail
        elif isinstance(exc.detail, list):
            details = {'errors': exc.detail}
        else:
            details = {'message': str(exc.detail)}
    elif hasattr(exc, 'message_dict'):
        # Django ValidationError
        details = exc.message_dict
    elif hasattr(exc, 'messages'):
        # Django ValidationError
        details = {'errors': exc.messages}
    else:
        details = {'message': str(exc)}
    
    return details


def _handle_non_api_exception(exc, request_id: Optional[str], view_name: str) -> StandardErrorResponse:
    """
    Handle non-API exceptions and convert them to standardized responses
    """
    if isinstance(exc, ValueError):
        return StandardErrorResponse.validation_error(
            message="Invalid value provided",
            request_id=request_id
        )
    
    elif isinstance(exc, TypeError):
        return StandardErrorResponse.validation_error(
            message="Invalid data type provided",
            request_id=request_id
        )
    
    elif isinstance(exc, KeyError):
        return StandardErrorResponse.validation_error(
            message="Required field missing",
            request_id=request_id
        )
    
    elif isinstance(exc, AttributeError):
        return StandardErrorResponse.server_error(
            message="Internal server error occurred",
            request_id=request_id
        )
    
    elif isinstance(exc, ImportError):
        return StandardErrorResponse.server_error(
            message="Service temporarily unavailable",
            request_id=request_id
        )
    
    elif isinstance(exc, ConnectionError):
        return StandardErrorResponse(
            error_code='CONNECTION_ERROR',
            message="Unable to connect to external service",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            request_id=request_id
        )
    
    elif isinstance(exc, TimeoutError):
        return StandardErrorResponse(
            error_code='TIMEOUT_ERROR',
            message="Request timed out",
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            request_id=request_id
        )
    
    else:
        # Generic server error for unknown exceptions
        return StandardErrorResponse.server_error(
            message="An unexpected error occurred. Please try again later.",
            request_id=request_id
        )


def _get_client_ip(request) -> str:
    """
    Get client IP address from request
    """
    if not request:
        return 'unknown'
    
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', 'unknown')
    return ip


def ensure_drf_response(view_func):
    """
    Decorator to ensure view functions return properly rendered DRF Response objects
    This prevents ContentNotRenderedError issues
    """
    from functools import wraps
    
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        try:
            response = view_func(*args, **kwargs)
            # Validate and ensure proper response type
            return validate_response_type(response)
        except Exception as exc:
            # If the view function fails, use the global exception handler
            request = None
            view = None
            
            # Try to extract request and view from args
            if args:
                if hasattr(args[0], 'request'):
                    request = args[0].request
                    view = args[0]
                elif hasattr(args[0], 'META'):  # Direct request object
                    request = args[0]
            
            context = {
                'view': view,
                'request': request
            }
            
            return global_exception_handler(exc, context)
    
    return wrapper


class ExceptionHandlerMixin:
    """
    Mixin for views that need custom exception handling
    """
    
    def handle_exception(self, exc):
        """
        Handle exceptions in views with standardized responses
        """
        request_id = getattr(self.request, 'request_id', None) if hasattr(self, 'request') else None
        
        # Log the exception
        logger.error(
            f"Exception in {self.__class__.__name__}: {type(exc).__name__}",
            extra={
                'request_id': request_id,
                'view_name': self.__class__.__name__,
                'exception_type': type(exc).__name__,
                'exception_message': str(exc)
            },
            exc_info=settings.DEBUG
        )
        
        # Use the global exception handler
        context = {
            'view': self,
            'request': getattr(self, 'request', None)
        }
        
        return global_exception_handler(exc, context)
    
    def dispatch(self, request, *args, **kwargs):
        """
        Override dispatch to ensure all responses are properly validated
        """
        try:
            response = super().dispatch(request, *args, **kwargs)
            return validate_response_type(response)
        except Exception as exc:
            return self.handle_exception(exc)


# Custom exception classes for specific business logic errors
class BusinessLogicError(APIException):
    """
    Exception for business logic violations
    """
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Business logic error occurred'
    default_code = 'business_logic_error'


class DataIntegrityError(APIException):
    """
    Exception for data integrity violations
    """
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'Data integrity constraint violated'
    default_code = 'data_integrity_error'


class ExternalServiceError(APIException):
    """
    Exception for external service failures
    """
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = 'External service unavailable'
    default_code = 'external_service_error'


class RateLimitExceededError(APIException):
    """
    Exception for rate limit violations
    """
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = 'Rate limit exceeded'
    default_code = 'rate_limit_exceeded'


class FileProcessingError(APIException):
    """
    Exception for file processing failures
    """
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'File processing failed'
    default_code = 'file_processing_error'