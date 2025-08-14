"""
Global Exception Handler for Django REST Framework
Provides consistent error handling across all API endpoints
"""

from typing import Optional, Dict, Any
from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError, PermissionDenied
from django.http import Http404
from rest_framework import status
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.response import Response
from rest_framework.exceptions import (
    APIException, AuthenticationFailed, NotAuthenticated,
    PermissionDenied as DRFPermissionDenied, NotFound,
    ValidationError as DRFValidationError, Throttled,
    ParseError, UnsupportedMediaType, MethodNotAllowed
)
from .error_response import StandardErrorResponse, SecureLogger

logger = SecureLogger(__name__)

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
        error_response = StandardErrorResponse.validation_error(
            message="Validation failed",
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
        allowed_methods = getattr(exc, 'detail', {}).get('allowed_methods', [])
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
        return error_response.to_response()
    
    # Fall back to DRF's default exception handler
    response = drf_exception_handler(exc, context)
    
    if response is not None:
        # Sanitize the DRF response
        error_response = StandardErrorResponse(
            error_code='API_ERROR',
            message=str(response.data) if response.data else 'An error occurred',
            status_code=response.status_code,
            request_id=request_id
        )
        return error_response.to_response()
    
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
            'exception_message': str(exc)
        },
        exc_info=settings.DEBUG
    )
    
    return error_response.to_response()


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