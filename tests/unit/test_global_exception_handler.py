"""
Test script for the enhanced global exception handler
Tests the fixes for ContentNotRenderedError and response rendering issues
"""

import os
import sys
import django
from django.conf import settings

# Add the backend directory to Python path
backend_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(backend_dir))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import RequestFactory
from django.template.response import ContentNotRenderedError, TemplateResponse
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework import status
from core_config.global_exception_handler import (
    global_exception_handler, 
    _ensure_response_rendered,
    validate_response_type
)


def test_content_not_rendered_error():
    """Test handling of ContentNotRenderedError"""
    print("Testing ContentNotRenderedError handling...")
    
    factory = RequestFactory()
    request = factory.post('/api/auth/login/')
    request.user = None
    
    context = {
        'request': request,
        'view': None
    }
    
    # Create ContentNotRenderedError
    exc = ContentNotRenderedError("The response content must be rendered before it can be accessed.")
    
    # Test the global exception handler
    response = global_exception_handler(exc, context)
    
    print(f"Response type: {type(response)}")
    print(f"Response status: {response.status_code}")
    print(f"Response data: {response.data}")
    print(f"Is rendered: {response.is_rendered}")
    
    assert isinstance(response, Response), "Should return DRF Response"
    assert response.status_code == 500, "Should return 500 status"
    assert response.is_rendered, "Response should be rendered"
    assert 'error' in response.data, "Should contain error data"
    
    print("✓ ContentNotRenderedError handling test passed")


def test_template_response_conversion():
    """Test conversion of TemplateResponse to DRF Response"""
    print("\nTesting TemplateResponse conversion...")
    
    # Create a mock TemplateResponse
    class MockTemplateResponse(TemplateResponse):
        def __init__(self):
            self.status_code = 200
            self._is_rendered = False
            
        def render(self):
            self._is_rendered = True
            self.content = b'{"message": "rendered"}'
            return self
    
    template_response = MockTemplateResponse()
    
    # Test the conversion
    converted_response = _ensure_response_rendered(template_response)
    
    print(f"Converted response type: {type(converted_response)}")
    print(f"Converted response status: {converted_response.status_code}")
    print(f"Is rendered: {converted_response.is_rendered}")
    
    assert isinstance(converted_response, Response), "Should convert to DRF Response"
    assert converted_response.is_rendered, "Should be rendered"
    
    print("✓ TemplateResponse conversion test passed")


def test_response_validation():
    """Test response type validation"""
    print("\nTesting response validation...")
    
    # Test DRF Response
    drf_response = Response({'message': 'test'}, status=200)
    validated = validate_response_type(drf_response)
    
    assert isinstance(validated, Response), "Should remain DRF Response"
    assert validated.is_rendered, "Should be rendered"
    
    # Test HttpResponse
    http_response = HttpResponse('{"message": "test"}', content_type='application/json')
    validated_http = validate_response_type(http_response)
    
    assert isinstance(validated_http, Response), "Should convert to DRF Response"
    
    print("✓ Response validation test passed")


def test_exception_handler_robustness():
    """Test exception handler with various exception types"""
    print("\nTesting exception handler robustness...")
    
    factory = RequestFactory()
    request = factory.post('/api/test/')
    
    context = {
        'request': request,
        'view': None
    }
    
    # Test various exception types
    exceptions_to_test = [
        ValueError("Test value error"),
        TypeError("Test type error"),
        KeyError("test_key"),
        AttributeError("Test attribute error"),
        ConnectionError("Test connection error"),
        TimeoutError("Test timeout error"),
    ]
    
    for exc in exceptions_to_test:
        response = global_exception_handler(exc, context)
        
        assert isinstance(response, Response), f"Should return DRF Response for {type(exc).__name__}"
        assert response.is_rendered, f"Should be rendered for {type(exc).__name__}"
        assert 'error' in response.data, f"Should contain error data for {type(exc).__name__}"
        
        print(f"✓ {type(exc).__name__} handled correctly")
    
    print("✓ Exception handler robustness test passed")


if __name__ == '__main__':
    print("Running Global Exception Handler Tests...")
    print("=" * 50)
    
    try:
        test_content_not_rendered_error()
        test_template_response_conversion()
        test_response_validation()
        test_exception_handler_robustness()
        
        print("\n" + "=" * 50)
        print("✅ All tests passed! Global exception handler is working correctly.")
        print("The ContentNotRenderedError issue should now be resolved.")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)