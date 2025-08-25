"""
Error Response Sanitization Middleware
Ensures all error responses are properly sanitized and formatted
"""

import json
import uuid
from typing import Any, Dict, Optional
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.core.exceptions import ValidationError, PermissionDenied
from rest_framework import status
from rest_framework.exceptions import (
    APIException, AuthenticationFailed, NotAuthenticated, 
    PermissionDenied as DRFPermissionDenied, NotFound,
    ValidationError as DRFValidationError, Throttled
)
from .error_response import StandardErrorResponse, SecureLogger

logger = SecureLogger(__name__)

class ErrorSanitizationMiddleware(MiddlewareMixin):
    """
    Middleware to sanitize all error responses and ensure consistent formatting
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """
        Add request ID for error tracking
        """
        if not hasattr(request, 'request_id'):
            request.request_id = str(uuid.uuid4())
        return None
    
    def process_exception(self, request, exception):
        """
        Process exceptions and return sanitized error responses
        """
        request_id = getattr(request, 'request_id', None)
        
        # Log the exception securely
        logger.error(
            f"Exception occurred: {type(exception).__name__}",
            extra={
                'request_id': request_id,
                'path': request.path,
                'method': request.method,
                'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'ip_address': self._get_client_ip(request),
                'exception_type': type(exception).__name__
            },
            exc_info=settings.DEBUG
        )
        
        # Handle different exception types
        if isinstance(exception, NotAuthenticated):
            error_response = StandardErrorResponse.authentication_error(
                message="Authentication credentials were not provided",
                request_id=request_id
            )
        
        elif isinstance(exception, AuthenticationFailed):
            error_response = StandardErrorResponse.authentication_error(
                message="Invalid authentication credentials",
                request_id=request_id
            )
        
        elif isinstance(exception, (PermissionDenied, DRFPermissionDenied)):
            error_response = StandardErrorResponse.permission_error(
                message="You do not have permission to perform this action",
                request_id=request_id
            )
            
            # Log permission denied event
            logger.log_permission_denied(
                user_id=getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                resource=request.path,
                action=request.method,
                ip_address=self._get_client_ip(request)
            )
        
        elif isinstance(exception, NotFound):
            error_response = StandardErrorResponse.not_found_error(
                message="The requested resource was not found",
                request_id=request_id
            )
        
        elif isinstance(exception, (ValidationError, DRFValidationError)):
            details = {}
            if hasattr(exception, 'detail'):
                if isinstance(exception.detail, dict):
                    details = exception.detail
                elif isinstance(exception.detail, list):
                    details = {'errors': exception.detail}
                else:
                    details = {'message': str(exception.detail)}
            
            error_response = StandardErrorResponse.validation_error(
                message="Validation failed",
                details=details,
                request_id=request_id
            )
        
        elif isinstance(exception, Throttled):
            retry_after = getattr(exception, 'wait', None)
            error_response = StandardErrorResponse.rate_limit_error(
                message="Rate limit exceeded. Please try again later.",
                retry_after=retry_after,
                request_id=request_id
            )
        
        elif isinstance(exception, APIException):
            # Generic API exception handling
            error_response = StandardErrorResponse(
                error_code='API_ERROR',
                message=str(exception.detail) if hasattr(exception, 'detail') else str(exception),
                status_code=getattr(exception, 'status_code', status.HTTP_500_INTERNAL_SERVER_ERROR),
                request_id=request_id
            )
        
        else:
            # Generic server error for unhandled exceptions
            error_response = StandardErrorResponse.server_error(
                message="An unexpected error occurred. Please try again later.",
                request_id=request_id
            )
            
            # Log unexpected errors as critical
            logger.critical(
                f"Unhandled exception: {type(exception).__name__}",
                extra={
                    'request_id': request_id,
                    'path': request.path,
                    'method': request.method,
                    'exception_message': str(exception)
                },
                exc_info=settings.DEBUG
            )
        
        return error_response.to_response()
    
    def process_response(self, request, response):
        """
        Process responses to ensure error responses are properly sanitized
        """
        # Only process error responses (4xx and 5xx status codes)
        if not (400 <= response.status_code < 600):
            return response
        
        request_id = getattr(request, 'request_id', None)
        
        try:
            # Check if response is already in our standard format
            if hasattr(response, 'data') and isinstance(response.data, dict):
                if 'error' in response.data:
                    # Handle both dict and string error formats
                    error_data = response.data['error']
                    
                    if isinstance(error_data, dict):
                        # Standard dictionary format
                        error_code = error_data.get('code', 'UNKNOWN_ERROR')
                        message = error_data.get('message', 'An error occurred')
                        details = error_data.get('details', {})
                    elif isinstance(error_data, str):
                        # String format - convert to standard format
                        error_code = self._get_error_code_from_status(response.status_code)
                        message = error_data
                        details = {}
                    else:
                        # Fallback for other types
                        error_code = self._get_error_code_from_status(response.status_code)
                        message = str(error_data) if error_data else 'An error occurred'
                        details = {}
                    
                    sanitized_response = StandardErrorResponse(
                        error_code=error_code,
                        message=message,
                        details=details,
                        status_code=response.status_code,
                        request_id=request_id
                    )
                    return sanitized_response.to_response()
            
            # Handle non-standard error responses
            if isinstance(response, JsonResponse):
                try:
                    # Try to parse existing JSON response
                    if hasattr(response, 'content'):
                        content = json.loads(response.content.decode('utf-8'))
                    else:
                        content = {}
                except (json.JSONDecodeError, UnicodeDecodeError):
                    content = {}
                
                # Create standardized error response
                error_response = StandardErrorResponse(
                    error_code=self._get_error_code_from_status(response.status_code),
                    message=content.get('message', content.get('detail', 'An error occurred')),
                    details=content if content else None,
                    status_code=response.status_code,
                    request_id=request_id
                )
                
                return error_response.to_response()
            
            elif isinstance(response, HttpResponse):
                # Handle non-JSON error responses
                error_response = StandardErrorResponse(
                    error_code=self._get_error_code_from_status(response.status_code),
                    message=self._get_message_from_status(response.status_code),
                    status_code=response.status_code,
                    request_id=request_id
                )
                
                return error_response.to_response()
        
            return response
        
        except Exception as e:
            # If error sanitization fails, create a safe fallback response
            logger.error(
                f"Error sanitization failed: {type(e).__name__}: {str(e)}",
                extra={
                    'request_id': request_id,
                    'path': request.path,
                    'method': request.method,
                    'original_status': response.status_code
                },
                exc_info=settings.DEBUG
            )
            
            # Create a safe fallback error response
            fallback_response = StandardErrorResponse(
                error_code=self._get_error_code_from_status(response.status_code),
                message=self._get_message_from_status(response.status_code),
                status_code=response.status_code,
                request_id=request_id
            )
            
            return fallback_response.to_response()
    
    def _get_client_ip(self, request) -> str:
        """
        Get client IP address from request
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip
    
    def _get_error_code_from_status(self, status_code: int) -> str:
        """
        Get error code from HTTP status code
        """
        error_codes = {
            400: 'BAD_REQUEST',
            401: 'AUTHENTICATION_ERROR',
            403: 'PERMISSION_DENIED',
            404: 'NOT_FOUND',
            405: 'METHOD_NOT_ALLOWED',
            406: 'NOT_ACCEPTABLE',
            408: 'REQUEST_TIMEOUT',
            409: 'CONFLICT',
            410: 'GONE',
            411: 'LENGTH_REQUIRED',
            412: 'PRECONDITION_FAILED',
            413: 'PAYLOAD_TOO_LARGE',
            414: 'URI_TOO_LONG',
            415: 'UNSUPPORTED_MEDIA_TYPE',
            416: 'RANGE_NOT_SATISFIABLE',
            417: 'EXPECTATION_FAILED',
            422: 'UNPROCESSABLE_ENTITY',
            423: 'LOCKED',
            424: 'FAILED_DEPENDENCY',
            426: 'UPGRADE_REQUIRED',
            428: 'PRECONDITION_REQUIRED',
            429: 'RATE_LIMIT_EXCEEDED',
            431: 'REQUEST_HEADER_FIELDS_TOO_LARGE',
            451: 'UNAVAILABLE_FOR_LEGAL_REASONS',
            500: 'INTERNAL_ERROR',
            501: 'NOT_IMPLEMENTED',
            502: 'BAD_GATEWAY',
            503: 'SERVICE_UNAVAILABLE',
            504: 'GATEWAY_TIMEOUT',
            505: 'HTTP_VERSION_NOT_SUPPORTED',
            507: 'INSUFFICIENT_STORAGE',
            508: 'LOOP_DETECTED',
            510: 'NOT_EXTENDED',
            511: 'NETWORK_AUTHENTICATION_REQUIRED'
        }
        
        return error_codes.get(status_code, 'UNKNOWN_ERROR')
    
    def _get_message_from_status(self, status_code: int) -> str:
        """
        Get user-friendly message from HTTP status code
        """
        messages = {
            400: 'Bad request',
            401: 'Authentication required',
            403: 'Permission denied',
            404: 'Resource not found',
            405: 'Method not allowed',
            406: 'Not acceptable',
            408: 'Request timeout',
            409: 'Conflict',
            410: 'Resource no longer available',
            411: 'Length required',
            412: 'Precondition failed',
            413: 'Request payload too large',
            414: 'Request URI too long',
            415: 'Unsupported media type',
            416: 'Range not satisfiable',
            417: 'Expectation failed',
            422: 'Unprocessable entity',
            423: 'Resource locked',
            424: 'Failed dependency',
            426: 'Upgrade required',
            428: 'Precondition required',
            429: 'Rate limit exceeded',
            431: 'Request header fields too large',
            451: 'Unavailable for legal reasons',
            500: 'Internal server error',
            501: 'Not implemented',
            502: 'Bad gateway',
            503: 'Service unavailable',
            504: 'Gateway timeout',
            505: 'HTTP version not supported',
            507: 'Insufficient storage',
            508: 'Loop detected',
            510: 'Not extended',
            511: 'Network authentication required'
        }
        
        return messages.get(status_code, 'An error occurred')


class SecurityEventMiddleware(MiddlewareMixin):
    """
    Middleware to log security-related events
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """
        Log security-relevant request information
        """
        # Log suspicious patterns in requests
        self._check_suspicious_patterns(request)
        return None
    
    def process_response(self, request, response):
        """
        Log security-relevant response information
        """
        # Log failed authentication attempts
        if response.status_code == 401:
            logger.log_authentication_attempt(
                username=request.POST.get('username', request.POST.get('email', 'unknown')),
                success=False,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', 'unknown')
            )
        
        # Log successful authentication
        elif response.status_code == 200 and request.path.endswith('/login/'):
            logger.log_authentication_attempt(
                username=request.POST.get('username', request.POST.get('email', 'unknown')),
                success=True,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', 'unknown')
            )
        
        return response
    
    def _check_suspicious_patterns(self, request):
        """
        Check for suspicious patterns in requests
        """
        suspicious_patterns = [
            'union select',
            'drop table',
            'insert into',
            'delete from',
            'update set',
            '<script',
            'javascript:',
            'eval(',
            'document.cookie',
            'window.location',
            '../../../',
            '..\\..\\',
            'cmd.exe',
            '/bin/bash',
            'passwd',
            '/etc/shadow'
        ]
        
        # Check query parameters
        query_string = request.META.get('QUERY_STRING', '').lower()
        for pattern in suspicious_patterns:
            if pattern in query_string:
                logger.log_suspicious_activity(
                    activity_type='suspicious_query_parameter',
                    ip_address=self._get_client_ip(request),
                    details={
                        'pattern': pattern,
                        'path': request.path,
                        'query_string': query_string[:200]  # Truncate for logging
                    }
                )
                break
        
        # Check POST data
        if request.method == 'POST' and hasattr(request, 'POST'):
            post_data = str(request.POST).lower()
            for pattern in suspicious_patterns:
                if pattern in post_data:
                    logger.log_suspicious_activity(
                        activity_type='suspicious_post_data',
                        ip_address=self._get_client_ip(request),
                        details={
                            'pattern': pattern,
                            'path': request.path
                        }
                    )
                    break
        
        # Check for unusual user agents
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'burp', 'owasp']
        for agent in suspicious_agents:
            if agent in user_agent:
                logger.log_suspicious_activity(
                    activity_type='suspicious_user_agent',
                    ip_address=self._get_client_ip(request),
                    details={
                        'user_agent': user_agent[:200],
                        'path': request.path
                    }
                )
                break
    
    def _get_client_ip(self, request) -> str:
        """
        Get client IP address from request
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip