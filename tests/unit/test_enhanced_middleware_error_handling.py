"""
Tests for Enhanced Middleware Error Handling

This module tests the enhanced error handling capabilities of critical middleware
to ensure they handle failures gracefully without causing 500 errors.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase, RequestFactory
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.template.response import ContentNotRenderedError
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.conf import settings

from .enhanced_middleware_error_handling import (
    EnhancedCommonMiddleware,
    EnhancedCsrfViewMiddleware,
    EnhancedAuthenticationMiddleware,
    EnhancedSessionMiddleware,
    MiddlewareErrorHandler,
    CriticalMiddlewareProtector
)
from .validation_middleware import InputValidationMiddleware, SecurityHeadersMiddleware, RateLimitMiddleware
from .middleware import RateLimitMiddleware as OriginalRateLimitMiddleware, SecurityMonitoringMiddleware


class TestEnhancedCommonMiddleware(TestCase):
    """Test enhanced CommonMiddleware error handling"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = EnhancedCommonMiddleware(lambda r: HttpResponse())
    
    def test_content_not_rendered_error_handling(self):
        """Test handling of ContentNotRenderedError"""
        request = self.factory.get('/api/test/')
        
        # Mock a response that raises ContentNotRenderedError
        mock_response = Mock()
        mock_response.render = Mock(side_effect=Exception("Render failed"))
        
        with patch.object(self.middleware.__class__.__bases__[0], 'process_response', 
                         side_effect=ContentNotRenderedError("Content not rendered")):
            
            result = self.middleware.process_response(request, mock_response)
            
            # Should return the original response without crashing
            self.assertEqual(result, mock_response)
    
    def test_attribute_error_handling(self):
        """Test handling of AttributeError in CommonMiddleware"""
        request = self.factory.get('/api/test/')
        response = HttpResponse()
        
        with patch.object(self.middleware.__class__.__bases__[0], 'process_response', 
                         side_effect=AttributeError("Missing attribute")):
            
            result = self.middleware.process_response(request, response)
            
            # Should return the original response without crashing
            self.assertEqual(result, response)
    
    def test_generic_exception_handling(self):
        """Test handling of generic exceptions in CommonMiddleware"""
        request = self.factory.get('/api/test/')
        response = HttpResponse()
        
        with patch.object(self.middleware.__class__.__bases__[0], 'process_response', 
                         side_effect=ValueError("Unexpected error")):
            
            result = self.middleware.process_response(request, response)
            
            # Should return the original response without crashing
            self.assertEqual(result, response)


class TestEnhancedCsrfViewMiddleware(TestCase):
    """Test enhanced CSRF middleware error handling"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = EnhancedCsrfViewMiddleware(lambda r: HttpResponse())
    
    def test_csrf_request_error_handling(self):
        """Test handling of errors in CSRF request processing"""
        request = self.factory.post('/api/test/')
        
        with patch.object(self.middleware.__class__.__bases__[0], 'process_request', 
                         side_effect=Exception("CSRF error")):
            
            result = self.middleware.process_request(request)
            
            # Should return JSON error response for API endpoints
            self.assertIsInstance(result, JsonResponse)
            self.assertEqual(result.status_code, 403)
    
    def test_csrf_view_error_handling(self):
        """Test handling of errors in CSRF view processing"""
        request = self.factory.post('/api/test/')
        callback = Mock()
        
        with patch.object(self.middleware.__class__.__bases__[0], 'process_view', 
                         side_effect=Exception("CSRF view error")):
            
            result = self.middleware.process_view(request, callback, (), {})
            
            # Should return JSON error response for API endpoints
            self.assertIsInstance(result, JsonResponse)
            self.assertEqual(result.status_code, 403)


class TestEnhancedAuthenticationMiddleware(TestCase):
    """Test enhanced Authentication middleware error handling"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = EnhancedAuthenticationMiddleware(lambda r: HttpResponse())
    
    def test_authentication_error_handling(self):
        """Test handling of authentication errors"""
        request = self.factory.get('/api/test/')
        
        with patch.object(self.middleware.__class__.__bases__[0], 'process_request', 
                         side_effect=Exception("Auth error")):
            
            # Should not raise exception
            self.middleware.process_request(request)
            
            # Should set anonymous user
            self.assertIsInstance(request.user, AnonymousUser)


class TestEnhancedSessionMiddleware(TestCase):
    """Test enhanced Session middleware error handling"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = EnhancedSessionMiddleware(lambda r: HttpResponse())
    
    def test_session_request_error_handling(self):
        """Test handling of session request errors"""
        request = self.factory.get('/api/test/')
        
        with patch.object(self.middleware.__class__.__bases__[0], 'process_request', 
                         side_effect=Exception("Session error")):
            
            # Should not raise exception
            self.middleware.process_request(request)
            
            # Should have a session object
            self.assertTrue(hasattr(request, 'session'))
    
    def test_session_response_error_handling(self):
        """Test handling of session response errors"""
        request = self.factory.get('/api/test/')
        response = HttpResponse()
        
        with patch.object(self.middleware.__class__.__bases__[0], 'process_response', 
                         side_effect=Exception("Session response error")):
            
            result = self.middleware.process_response(request, response)
            
            # Should return the original response
            self.assertEqual(result, response)


class TestMiddlewareErrorHandler(TestCase):
    """Test generic middleware error handler"""
    
    def setUp(self):
        self.factory = RequestFactory()
        
        def mock_get_response(request):
            raise ContentNotRenderedError("Content not rendered")
        
        self.middleware = MiddlewareErrorHandler(mock_get_response)
    
    def test_content_not_rendered_error_api(self):
        """Test ContentNotRenderedError handling for API endpoints"""
        request = self.factory.get('/api/test/')
        
        response = self.middleware(request)
        
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_content_not_rendered_error_non_api(self):
        """Test ContentNotRenderedError handling for non-API endpoints"""
        request = self.factory.get('/admin/test/')
        
        response = self.middleware(request)
        
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response['Content-Type'], 'text/html')
    
    def test_generic_error_handling(self):
        """Test generic error handling"""
        def mock_get_response(request):
            raise ValueError("Generic error")
        
        middleware = MiddlewareErrorHandler(mock_get_response)
        request = self.factory.get('/api/test/')
        
        response = middleware(request)
        
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response['Content-Type'], 'application/json')


class TestCriticalMiddlewareProtector(TestCase):
    """Test critical middleware protector"""
    
    def setUp(self):
        self.factory = RequestFactory()
        
        def mock_get_response(request):
            raise ContentNotRenderedError("Content not rendered")
        
        self.middleware = CriticalMiddlewareProtector(mock_get_response)
    
    def test_request_context_setup(self):
        """Test that error handling context is set up"""
        request = self.factory.get('/api/test/')
        
        self.middleware.process_request(request)
        
        self.assertTrue(hasattr(request, '_middleware_error_context'))
        self.assertIn('path', request._middleware_error_context)
        self.assertIn('method', request._middleware_error_context)
    
    def test_exception_handling(self):
        """Test exception handling in critical middleware protector"""
        request = self.factory.get('/api/test/')
        request._middleware_error_context = {'path': '/api/test/', 'method': 'GET', 'errors': []}
        
        exception = ContentNotRenderedError("Content not rendered")
        
        response = self.middleware.process_exception(request, exception)
        
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 500)


class TestValidationMiddlewareErrorHandling(TestCase):
    """Test enhanced validation middleware error handling"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = InputValidationMiddleware(lambda r: HttpResponse())
    
    def test_attribute_error_handling(self):
        """Test handling of AttributeError in validation middleware"""
        request = self.factory.post('/api/test/', data={'test': 'data'})
        
        with patch.object(self.middleware, '_validate_csrf_token', 
                         side_effect=AttributeError("Missing attribute")):
            
            result = self.middleware.process_request(request)
            
            # Should return None to continue processing
            self.assertIsNone(result)
    
    def test_value_error_handling(self):
        """Test handling of ValueError in validation middleware"""
        request = self.factory.post('/api/test/', data={'test': 'data'})
        
        with patch.object(self.middleware, '_validate_request_data', 
                         side_effect=ValueError("Invalid value")):
            
            result = self.middleware.process_request(request)
            
            # Should return JSON error response
            self.assertIsInstance(result, JsonResponse)
            self.assertEqual(result.status_code, 400)


class TestRateLimitMiddlewareErrorHandling(TestCase):
    """Test enhanced rate limit middleware error handling"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = RateLimitMiddleware(lambda r: HttpResponse())
    
    def test_connection_error_handling(self):
        """Test handling of Redis connection errors"""
        request = self.factory.get('/api/test/')
        
        with patch.object(self.middleware, '_is_rate_limited', 
                         side_effect=ConnectionError("Redis connection failed")):
            
            result = self.middleware.process_request(request)
            
            # Should return None to allow request to continue
            self.assertIsNone(result)
    
    def test_generic_error_handling(self):
        """Test handling of generic errors in rate limiting"""
        request = self.factory.get('/api/test/')
        
        with patch.object(self.middleware, '_get_client_ip', 
                         side_effect=Exception("Unexpected error")):
            
            result = self.middleware.process_request(request)
            
            # Should return None to allow request to continue
            self.assertIsNone(result)


class TestSecurityHeadersMiddlewareErrorHandling(TestCase):
    """Test enhanced security headers middleware error handling"""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = SecurityHeadersMiddleware(lambda r: HttpResponse())
    
    def test_attribute_error_handling(self):
        """Test handling of AttributeError when setting headers"""
        request = self.factory.get('/api/test/')
        
        # Mock response that doesn't support header setting
        mock_response = Mock()
        mock_response.__setitem__ = Mock(side_effect=AttributeError("No header support"))
        
        result = self.middleware.process_response(request, mock_response)
        
        # Should return the response without crashing
        self.assertEqual(result, mock_response)
    
    def test_generic_error_handling(self):
        """Test handling of generic errors in security headers"""
        request = self.factory.get('/api/test/')
        response = HttpResponse()
        
        with patch.object(response, '__setitem__', side_effect=Exception("Header error")):
            
            result = self.middleware.process_response(request, response)
            
            # Should return the response without crashing
            self.assertEqual(result, response)


@pytest.mark.django_db
class TestMiddlewareIntegration(TestCase):
    """Integration tests for enhanced middleware error handling"""
    
    def setUp(self):
        self.factory = RequestFactory()
    
    def test_middleware_chain_with_errors(self):
        """Test that middleware chain continues even with errors"""
        request = self.factory.get('/api/test/')
        
        # Create a chain of middleware with potential errors
        def final_response(req):
            return HttpResponse("Success")
        
        # Chain middleware together
        middleware_chain = CriticalMiddlewareProtector(
            MiddlewareErrorHandler(
                EnhancedCommonMiddleware(final_response)
            )
        )
        
        # Process request through the chain
        middleware_chain.process_request(request)
        response = middleware_chain(request)
        
        # Should get a response (either success or error, but not crash)
        self.assertIsInstance(response, HttpResponse)
    
    def test_api_error_responses_are_json(self):
        """Test that API endpoints always get JSON error responses"""
        request = self.factory.get('/api/test/')
        
        def error_response(req):
            raise ContentNotRenderedError("Content not rendered")
        
        middleware = MiddlewareErrorHandler(error_response)
        response = middleware(request)
        
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertEqual(response.status_code, 500)
    
    def test_non_api_error_responses_are_html(self):
        """Test that non-API endpoints get HTML error responses"""
        request = self.factory.get('/admin/test/')
        
        def error_response(req):
            raise ContentNotRenderedError("Content not rendered")
        
        middleware = MiddlewareErrorHandler(error_response)
        response = middleware(request)
        
        self.assertEqual(response['Content-Type'], 'text/html')
        self.assertEqual(response.status_code, 500)


if __name__ == '__main__':
    pytest.main([__file__])