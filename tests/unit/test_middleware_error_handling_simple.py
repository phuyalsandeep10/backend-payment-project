"""
Simple tests for Enhanced Middleware Error Handling

This module provides basic unit tests for the enhanced error handling capabilities
without requiring full database setup.
"""

import os
import sys
import django
from django.conf import settings

# Configure Django settings before importing Django modules
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='test-secret-key-for-middleware-tests',
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'core_config',
        ],
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },
        USE_TZ=True,
        LOGGING={
            'version': 1,
            'disable_existing_loggers': False,
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                },
            },
            'loggers': {
                'security': {
                    'handlers': ['console'],
                    'level': 'INFO',
                },
                'performance': {
                    'handlers': ['console'],
                    'level': 'INFO',
                },
            },
        }
    )

django.setup()

import unittest
from unittest.mock import Mock, patch, MagicMock
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.template.response import ContentNotRenderedError
from django.test import RequestFactory

# Import the enhanced middleware classes
from .enhanced_middleware_error_handling import (
    EnhancedCommonMiddleware,
    MiddlewareErrorHandler,
    CriticalMiddlewareProtector
)


class TestEnhancedMiddlewareErrorHandling(unittest.TestCase):
    """Test enhanced middleware error handling without database dependencies"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
    
    def test_enhanced_common_middleware_content_error(self):
        """Test EnhancedCommonMiddleware handles ContentNotRenderedError"""
        # Create middleware instance
        middleware = EnhancedCommonMiddleware(lambda r: HttpResponse())
        
        # Create test request and response
        request = self.factory.get('/api/test/')
        response = HttpResponse()
        
        # Mock the parent class to raise ContentNotRenderedError
        with patch.object(middleware.__class__.__bases__[0], 'process_response', 
                         side_effect=ContentNotRenderedError("Content not rendered")):
            
            # Should not raise exception
            result = middleware.process_response(request, response)
            
            # Should return the original response
            self.assertEqual(result, response)
    
    def test_enhanced_common_middleware_attribute_error(self):
        """Test EnhancedCommonMiddleware handles AttributeError"""
        middleware = EnhancedCommonMiddleware(lambda r: HttpResponse())
        request = self.factory.get('/api/test/')
        response = HttpResponse()
        
        # Mock the parent class to raise AttributeError
        with patch.object(middleware.__class__.__bases__[0], 'process_response', 
                         side_effect=AttributeError("Missing attribute")):
            
            result = middleware.process_response(request, response)
            self.assertEqual(result, response)
    
    def test_enhanced_common_middleware_generic_error(self):
        """Test EnhancedCommonMiddleware handles generic exceptions"""
        middleware = EnhancedCommonMiddleware(lambda r: HttpResponse())
        request = self.factory.get('/api/test/')
        response = HttpResponse()
        
        # Mock the parent class to raise generic exception
        with patch.object(middleware.__class__.__bases__[0], 'process_response', 
                         side_effect=ValueError("Unexpected error")):
            
            result = middleware.process_response(request, response)
            self.assertEqual(result, response)
    
    def test_middleware_error_handler_content_error_api(self):
        """Test MiddlewareErrorHandler handles ContentNotRenderedError for API"""
        def mock_get_response(request):
            raise ContentNotRenderedError("Content not rendered")
        
        middleware = MiddlewareErrorHandler(mock_get_response)
        request = self.factory.get('/api/test/')
        
        response = middleware(request)
        
        # Should return JSON error response
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_middleware_error_handler_content_error_non_api(self):
        """Test MiddlewareErrorHandler handles ContentNotRenderedError for non-API"""
        def mock_get_response(request):
            raise ContentNotRenderedError("Content not rendered")
        
        middleware = MiddlewareErrorHandler(mock_get_response)
        request = self.factory.get('/admin/test/')
        
        response = middleware(request)
        
        # Should return HTML error response
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response['Content-Type'], 'text/html')
    
    def test_middleware_error_handler_generic_error(self):
        """Test MiddlewareErrorHandler handles generic exceptions"""
        def mock_get_response(request):
            raise ValueError("Generic error")
        
        middleware = MiddlewareErrorHandler(mock_get_response)
        request = self.factory.get('/api/test/')
        
        response = middleware(request)
        
        # Should return JSON error response
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_critical_middleware_protector_setup(self):
        """Test CriticalMiddlewareProtector sets up error context"""
        middleware = CriticalMiddlewareProtector(lambda r: HttpResponse())
        request = self.factory.get('/api/test/')
        
        # Process request should set up error context
        middleware.process_request(request)
        
        # Check that error context is set up
        self.assertTrue(hasattr(request, '_middleware_error_context'))
        self.assertIn('path', request._middleware_error_context)
        self.assertIn('method', request._middleware_error_context)
        self.assertIn('errors', request._middleware_error_context)
    
    def test_critical_middleware_protector_exception_handling(self):
        """Test CriticalMiddlewareProtector handles exceptions"""
        middleware = CriticalMiddlewareProtector(lambda r: HttpResponse())
        request = self.factory.get('/api/test/')
        
        # Set up error context
        request._middleware_error_context = {
            'path': '/api/test/',
            'method': 'GET',
            'errors': []
        }
        
        # Test exception handling
        exception = ContentNotRenderedError("Content not rendered")
        response = middleware.process_exception(request, exception)
        
        # Should return JSON error response
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 500)
    
    def test_error_logging_without_sensitive_info(self):
        """Test that error logging doesn't expose sensitive information"""
        middleware = EnhancedCommonMiddleware(lambda r: HttpResponse())
        request = self.factory.post('/api/auth/login/')
        request.POST = {'password': 'secret123', 'username': 'testuser'}
        response = HttpResponse()
        
        # Mock logger to capture log calls
        with patch('core_config.enhanced_middleware_error_handling.logger') as mock_logger:
            with patch.object(middleware.__class__.__bases__[0], 'process_response', 
                             side_effect=Exception("Test error")):
                
                middleware.process_response(request, response)
                
                # Check that logger was called
                self.assertTrue(mock_logger.error.called)
                
                # Get the log call arguments
                call_args = mock_logger.error.call_args
                
                # Ensure sensitive data is not in the log message
                log_message = str(call_args)
                self.assertNotIn('secret123', log_message)
                self.assertNotIn('password', log_message.lower())
    
    def test_graceful_degradation(self):
        """Test that middleware fails gracefully and allows requests to continue"""
        # Test that even when middleware fails, the request can still be processed
        def failing_middleware(request):
            raise Exception("Middleware failure")
        
        middleware = MiddlewareErrorHandler(failing_middleware)
        request = self.factory.get('/api/test/')
        
        # Should not raise exception, should return error response
        response = middleware(request)
        
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.status_code, 500)
    
    def test_api_vs_non_api_response_types(self):
        """Test that API and non-API endpoints get appropriate response types"""
        def failing_middleware(request):
            raise ContentNotRenderedError("Content error")
        
        middleware = MiddlewareErrorHandler(failing_middleware)
        
        # Test API endpoint
        api_request = self.factory.get('/api/test/')
        api_response = middleware(api_request)
        self.assertEqual(api_response['Content-Type'], 'application/json')
        
        # Test non-API endpoint
        web_request = self.factory.get('/admin/test/')
        web_response = middleware(web_request)
        self.assertEqual(web_response['Content-Type'], 'text/html')
    
    def test_error_context_preservation(self):
        """Test that error context is preserved through middleware chain"""
        middleware = CriticalMiddlewareProtector(lambda r: HttpResponse())
        request = self.factory.get('/api/test/')
        
        # Set up request
        middleware.process_request(request)
        
        # Simulate exception
        exception = ValueError("Test error")
        response = middleware.process_exception(request, exception)
        
        # Check that error context was updated
        self.assertIn('errors', request._middleware_error_context)
        self.assertEqual(len(request._middleware_error_context['errors']), 1)
        self.assertEqual(
            request._middleware_error_context['errors'][0]['exception_type'],
            'ValueError'
        )


class TestMiddlewareErrorHandlingIntegration(unittest.TestCase):
    """Integration tests for middleware error handling"""
    
    def setUp(self):
        self.factory = RequestFactory()
    
    def test_middleware_chain_resilience(self):
        """Test that middleware chain is resilient to individual middleware failures"""
        # Create a chain where one middleware fails
        def failing_middleware(request):
            if request.path == '/api/fail/':
                raise ContentNotRenderedError("Middleware failed")
            return HttpResponse("Success")
        
        # Wrap with error handler
        protected_middleware = MiddlewareErrorHandler(failing_middleware)
        
        # Test successful request
        success_request = self.factory.get('/api/success/')
        success_response = protected_middleware(success_request)
        self.assertEqual(success_response.status_code, 200)
        
        # Test failing request
        fail_request = self.factory.get('/api/fail/')
        fail_response = protected_middleware(fail_request)
        self.assertEqual(fail_response.status_code, 500)
        self.assertEqual(fail_response['Content-Type'], 'application/json')
    
    def test_multiple_error_handlers(self):
        """Test multiple error handlers in the middleware chain"""
        def inner_failing_middleware(request):
            raise ValueError("Inner failure")
        
        # Chain multiple error handlers
        middleware_chain = CriticalMiddlewareProtector(
            MiddlewareErrorHandler(inner_failing_middleware)
        )
        
        request = self.factory.get('/api/test/')
        
        # Set up request context
        middleware_chain.process_request(request)
        
        # Process the request
        response = middleware_chain(request)
        
        # Should get an error response, not crash
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.status_code, 500)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)