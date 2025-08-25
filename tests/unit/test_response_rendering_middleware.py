"""
Tests for Response Rendering Middleware
"""

import pytest
from unittest.mock import Mock, patch
from django.test import TestCase, RequestFactory
from django.http import HttpRequest, HttpResponse
from django.template.response import TemplateResponse
from django.template import Template, Context
from rest_framework.response import Response as DRFResponse
from rest_framework import status

from .response_rendering_middleware import (
    ResponseRenderingMiddleware,
    ResponseTypeValidationMiddleware,
    ContentAccessProtectionMiddleware
)


class TestResponseRenderingMiddleware(TestCase):
    """Test cases for ResponseRenderingMiddleware"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
        self.request = self.factory.get('/api/test/')
        
        # Mock get_response function
        self.mock_get_response = Mock()
        
        # Initialize middleware
        self.middleware = ResponseRenderingMiddleware(self.mock_get_response)
    
    def test_regular_http_response_passthrough(self):
        """Test that regular HttpResponse objects pass through unchanged"""
        # Create a regular HttpResponse
        response = HttpResponse('Test content', content_type='text/plain')
        self.mock_get_response.return_value = response
        
        # Process through middleware
        result = self.middleware(self.request)
        
        # Should return the same response
        self.assertEqual(result, response)
        self.assertEqual(result.content, b'Test content')
    
    def test_drf_response_passthrough(self):
        """Test that DRF Response objects pass through unchanged"""
        # Create a DRF Response
        response = DRFResponse({'message': 'test'}, status=status.HTTP_200_OK)
        self.mock_get_response.return_value = response
        
        # Process through middleware
        result = self.middleware(self.request)
        
        # Should return the same response
        self.assertEqual(result, response)
    
    def test_template_response_rendering(self):
        """Test that TemplateResponse objects are rendered"""
        # Create a simple template
        template = Template('Hello {{ name }}!')
        
        # Create an unrendered TemplateResponse
        response = TemplateResponse(self.request, template, {'name': 'World'})
        self.assertFalse(response.is_rendered)
        
        self.mock_get_response.return_value = response
        
        # Process through middleware
        result = self.middleware(self.request)
        
        # Should be rendered now
        self.assertTrue(result.is_rendered)
        self.assertEqual(result.content, b'Hello World!')
    
    def test_already_rendered_template_response(self):
        """Test that already rendered TemplateResponse objects are not re-rendered"""
        # Create a simple template
        template = Template('Hello {{ name }}!')
        
        # Create and render a TemplateResponse
        response = TemplateResponse(self.request, template, {'name': 'World'})
        response.render()  # Pre-render
        self.assertTrue(response.is_rendered)
        
        self.mock_get_response.return_value = response
        
        # Process through middleware
        result = self.middleware(self.request)
        
        # Should still be rendered and unchanged
        self.assertTrue(result.is_rendered)
        self.assertEqual(result.content, b'Hello World!')
    
    @patch('core_config.response_rendering_middleware.logger')
    def test_template_response_rendering_logs(self, mock_logger):
        """Test that template response rendering is logged"""
        # Create a simple template
        template = Template('Hello {{ name }}!')
        
        # Create an unrendered TemplateResponse
        response = TemplateResponse(self.request, template, {'name': 'World'})
        self.mock_get_response.return_value = response
        
        # Process through middleware
        result = self.middleware(self.request)
        
        # Should log the rendering
        mock_logger.info.assert_called()
        mock_logger.debug.assert_called()
    
    @patch('core_config.response_rendering_middleware.logger')
    def test_exception_handling_creates_fallback(self, mock_logger):
        """Test that exceptions during rendering create fallback responses"""
        # Create a mock response that raises an exception when content is accessed
        mock_response = Mock()
        mock_response.content = Mock(side_effect=Exception("Test exception"))
        
        self.mock_get_response.return_value = mock_response
        
        # Process through middleware
        result = self.middleware(self.request)
        
        # Should create a fallback response
        self.assertIsInstance(result, HttpResponse)
        self.assertEqual(result.status_code, 500)
        self.assertIn(b'RESPONSE_RENDERING_ERROR', result.content)
        
        # Should log the error
        mock_logger.error.assert_called()
    
    def test_fallback_response_creation(self):
        """Test fallback response creation"""
        exception = Exception("Test exception")
        
        # Test fallback response creation
        fallback = self.middleware._create_fallback_response(self.request, exception)
        
        self.assertIsInstance(fallback, HttpResponse)
        self.assertEqual(fallback.status_code, 500)
        self.assertEqual(fallback['Content-Type'], 'application/json')
        self.assertIn(b'RESPONSE_RENDERING_ERROR', fallback.content)


class TestResponseTypeValidationMiddleware(TestCase):
    """Test cases for ResponseTypeValidationMiddleware"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
        self.middleware = ResponseTypeValidationMiddleware()
    
    @patch('core_config.response_rendering_middleware.logger')
    def test_api_endpoint_response_logging(self, mock_logger):
        """Test that API endpoint responses are logged"""
        request = self.factory.get('/api/test/')
        response = HttpResponse('Test content')
        
        # Process through middleware
        result = self.middleware.process_response(request, response)
        
        # Should log response type information
        mock_logger.debug.assert_called()
        
        # Should return unchanged response
        self.assertEqual(result, response)
    
    def test_non_api_endpoint_no_logging(self):
        """Test that non-API endpoints are not logged"""
        request = self.factory.get('/admin/test/')
        response = HttpResponse('Test content')
        
        with patch('core_config.response_rendering_middleware.logger') as mock_logger:
            # Process through middleware
            result = self.middleware.process_response(request, response)
            
            # Should not log for non-API endpoints
            mock_logger.debug.assert_not_called()
            
            # Should return unchanged response
            self.assertEqual(result, response)
    
    @patch('core_config.response_rendering_middleware.logger')
    def test_unrendered_template_response_warning(self, mock_logger):
        """Test that unrendered template responses generate warnings"""
        request = self.factory.get('/api/test/')
        template = Template('Hello {{ name }}!')
        response = TemplateResponse(request, template, {'name': 'World'})
        
        # Process through middleware (response should be unrendered)
        result = self.middleware.process_response(request, response)
        
        # Should log warning about unrendered template response
        mock_logger.warning.assert_called()
        
        # Should return unchanged response
        self.assertEqual(result, response)


class TestContentAccessProtectionMiddleware(TestCase):
    """Test cases for ContentAccessProtectionMiddleware"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
        self.request = self.factory.get('/api/test/')
        
        # Mock get_response function
        self.mock_get_response = Mock()
        
        # Initialize middleware
        self.middleware = ContentAccessProtectionMiddleware(self.mock_get_response)
    
    def test_normal_response_content_access(self):
        """Test that normal responses with accessible content pass through"""
        response = HttpResponse('Test content')
        self.mock_get_response.return_value = response
        
        # Process through middleware
        result = self.middleware(self.request)
        
        # Should return the same response
        self.assertEqual(result, response)
        self.assertEqual(result.content, b'Test content')
    
    @patch('core_config.response_rendering_middleware.logger')
    def test_content_access_error_handling(self, mock_logger):
        """Test handling of content access errors"""
        # Create a mock response that raises an exception when content is accessed
        mock_response = Mock()
        mock_response.content = Mock(side_effect=Exception("Content access error"))
        
        self.mock_get_response.return_value = mock_response
        
        # Process through middleware
        result = self.middleware(self.request)
        
        # Should log the error
        mock_logger.error.assert_called()
        
        # Should return the response (even if problematic)
        self.assertEqual(result, mock_response)
    
    @patch('core_config.response_rendering_middleware.logger')
    def test_template_response_rendering_on_content_error(self, mock_logger):
        """Test that template responses are rendered when content access fails"""
        # Create a template response that initially fails content access
        template = Template('Hello {{ name }}!')
        response = TemplateResponse(self.request, template, {'name': 'World'})
        
        # Mock content access to fail initially
        original_content = response.content
        with patch.object(response, 'content', side_effect=[Exception("Access error"), original_content]):
            self.mock_get_response.return_value = response
            
            # Process through middleware
            result = self.middleware(self.request)
            
            # Should log the error and successful rendering
            mock_logger.error.assert_called()
            mock_logger.info.assert_called()
            
            # Response should be rendered
            self.assertTrue(result.is_rendered)


if __name__ == '__main__':
    pytest.main([__file__])