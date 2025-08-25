"""
SQL Injection Detection Middleware
Monitors and prevents SQL injection attempts in real-time
"""
import re
import logging
from django.http import HttpResponseBadRequest
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

logger = logging.getLogger('security')

class SQLInjectionDetectionMiddleware(MiddlewareMixin):
    """
    Middleware to detect and prevent SQL injection attempts
    """
    
    # Common SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\b(OR|AND)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
        r"(UNION\s+(ALL\s+)?SELECT)",
        r"(INSERT\s+INTO)",
        r"(UPDATE\s+\w+\s+SET)",
        r"(DELETE\s+FROM)",
        r"(DROP\s+(TABLE|DATABASE|INDEX))",
        r"(CREATE\s+(TABLE|DATABASE|INDEX))",
        r"(ALTER\s+TABLE)",
        r"(EXEC\s*\()",
        r"(SCRIPT\s*>)",
        r"(\bxp_cmdshell\b)",
        r"(\bsp_executesql\b)",
        r"(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER))",
        r"(';\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER))",
        r"(\"\s*;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER))",
    ]
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Compile regex patterns for better performance
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS
        ]
        super().__init__(get_response)
    
    def process_request(self, request):
        """
        Check request for SQL injection attempts
        """
        # Skip checking for certain paths (admin, static files, etc.)
        if self._should_skip_check(request):
            return None
        
        # Check GET parameters
        if self._check_query_params(request.GET):
            return self._handle_sql_injection_attempt(request, 'GET parameters')
        
        # Check POST/multipart data safely
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_type = request.META.get('CONTENT_TYPE', '').lower()
            
            # Handle form data (both URL-encoded and multipart)
            if ('application/x-www-form-urlencoded' in content_type or 
                'multipart/form-data' in content_type):
                try:
                    # For multipart and form data, check POST dict (avoids reading body directly)
                    if hasattr(request, 'POST') and self._check_query_params(request.POST):
                        return self._handle_sql_injection_attempt(request, 'POST data')
                except Exception:
                    # POST data already read or not accessible, skip this check
                    pass
            
            # Handle JSON data (avoid reading body for multipart to prevent RawPostDataException)
            elif ('application/json' in content_type or 
                  'text/' in content_type or
                  (content_type == '' and 'multipart/form-data' not in content_type)):
                try:
                    # Use a custom method to safely read body
                    body_str = self._safe_read_body(request)
                    if body_str and self._check_string_for_sql_injection(body_str):
                        return self._handle_sql_injection_attempt(request, 'request body')
                except Exception:
                    # Skip any errors in body reading
                    pass
        
        return None
    
    def _should_skip_check(self, request):
        """
        Determine if we should skip SQL injection checking for this request
        """
        skip_paths = [
            '/admin/',
            '/static/',
            '/media/',
            '/favicon.ico',
            '/api/deals/',  # Skip deals endpoints - they have their own validation
            '/api/clients/',  # Skip clients endpoints - they have their own validation
        ]
        
        # Skip if path starts with any of the skip paths
        for skip_path in skip_paths:
            if request.path.startswith(skip_path):
                return True
        
        # Skip if this is a health check or monitoring endpoint
        if request.path in ['/health/', '/status/', '/ping/']:
            return True
        
        # Skip chunked upload endpoints (these handle files differently)
        if '/chunked-upload/' in request.path:
            return True
        
        return False
    
    def _check_query_params(self, params):
        """
        Check query parameters for SQL injection patterns
        """
        for key, values in params.items():
            # Handle both single values and lists
            if isinstance(values, list):
                for value in values:
                    if self._check_string_for_sql_injection(str(value)):
                        return True
            else:
                if self._check_string_for_sql_injection(str(values)):
                    return True
        return False
    
    def _check_string_for_sql_injection(self, input_string):
        """
        Check a string for SQL injection patterns
        """
        if not input_string:
            return False
        
        # Check against all compiled patterns
        for pattern in self.compiled_patterns:
            if pattern.search(input_string):
                return True
        
        return False
    
    def _safe_read_body(self, request):
        """
        Safely read request body without causing RawPostDataException
        """
        try:
            # Check if body has already been read
            if hasattr(request, '_body'):
                return request._body.decode('utf-8') if request._body else None
            
            # Try to read body if it hasn't been read yet
            if hasattr(request, 'body'):
                return request.body.decode('utf-8')
            
            return None
        except Exception:
            # If anything goes wrong, just skip the check
            return None
    
    def _handle_sql_injection_attempt(self, request, source):
        """
        Handle detected SQL injection attempt
        """
        # Log the security incident
        logger.warning(
            f"SQL injection attempt detected from {request.META.get('REMOTE_ADDR', 'unknown')} "
            f"in {source}. Path: {request.path}, User-Agent: {request.META.get('HTTP_USER_AGENT', 'unknown')}"
        )
        
        # Log additional details if available
        if hasattr(request, 'user') and request.user.is_authenticated:
            logger.warning(f"SQL injection attempt by authenticated user: {request.user.username}")
        
        # In production, you might want to:
        # 1. Block the IP address
        # 2. Send alerts to security team
        # 3. Log to external security monitoring system
        
        # Return bad request response
        if getattr(settings, 'DEBUG', False):
            return HttpResponseBadRequest("SQL injection attempt detected and blocked")
        else:
            # In production, don't reveal the reason for security
            return HttpResponseBadRequest("Invalid request")


class SQLQueryLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log all SQL queries for security monitoring
    Only active in DEBUG mode or when explicitly enabled
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_response(self, request, response):
        """
        Log SQL queries if monitoring is enabled
        """
        # Only log if DEBUG is True or SQL_QUERY_LOGGING is explicitly enabled
        if getattr(settings, 'DEBUG', False) or getattr(settings, 'SQL_QUERY_LOGGING', False):
            from django.db import connection
            
            # Log number of queries
            query_count = len(connection.queries)
            if query_count > 0:
                logger.info(f"SQL queries for {request.path}: {query_count} queries")
                
                # Log slow queries (>100ms)
                slow_queries = [
                    q for q in connection.queries 
                    if float(q.get('time', 0)) > 0.1
                ]
                
                if slow_queries:
                    logger.warning(f"Slow queries detected on {request.path}: {len(slow_queries)} queries")
                    for query in slow_queries:
                        logger.warning(f"Slow query ({query['time']}s): {query['sql'][:200]}...")
        
        return response