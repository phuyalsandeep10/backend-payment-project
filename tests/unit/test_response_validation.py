#!/usr/bin/env python
"""
Simple test script to verify response validation decorators work correctly.
This can be run independently without Django test framework.
"""

import sys
import os
import django
from unittest.mock import MagicMock, patch

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.http import JsonResponse, HttpResponse
from django.template.response import TemplateResponse
from rest_framework.response import Response
from authentication.response_validators import validate_response_type, ensure_drf_response, log_response_type

def test_validate_response_type_decorator():
    """Test that the validate_response_type decorator works correctly."""
    print("Testing validate_response_type decorator...")
    
    # Test with DRF Response (should pass through unchanged)
    @validate_response_type
    def view_with_drf_response():
        return Response({'test': 'data'})
    
    response = view_with_drf_response()
    assert isinstance(response, Response), f"Expected Response, got {type(response)}"
    assert response.data == {'test': 'data'}, f"Expected data to be preserved"
    print("✓ DRF Response passes through correctly")
    
    # Test with TemplateResponse (should be converted)
    @validate_response_type
    def view_with_template_response():
        template_response = TemplateResponse(
            request=MagicMock(),
            template='test.html',
            context={'test': 'data'}
        )
        # Mock the render method
        template_response.render = MagicMock()
        template_response.status_code = 200
        template_response.content = b'{"test": "data"}'
        return template_response
    
    response = view_with_template_response()
    assert isinstance(response, Response), f"Expected Response, got {type(response)}"
    print("✓ TemplateResponse converted to DRF Response")
    
    # Test with JsonResponse (should be allowed but logged)
    @validate_response_type
    def view_with_json_response():
        return JsonResponse({'test': 'data'})
    
    response = view_with_json_response()
    assert isinstance(response, JsonResponse), f"Expected JsonResponse, got {type(response)}"
    print("✓ JsonResponse allowed to pass through")

def test_ensure_drf_response_decorator():
    """Test that the ensure_drf_response decorator works correctly."""
    print("\nTesting ensure_drf_response decorator...")
    
    # Test with DRF Response (should pass through unchanged)
    @ensure_drf_response
    def view_with_drf_response():
        return Response({'test': 'data'})
    
    response = view_with_drf_response()
    assert isinstance(response, Response), f"Expected Response, got {type(response)}"
    assert response.data == {'test': 'data'}, f"Expected data to be preserved"
    print("✓ DRF Response passes through correctly")
    
    # Test with JsonResponse (should be converted)
    @ensure_drf_response
    def view_with_json_response():
        return JsonResponse({'test': 'data'})
    
    response = view_with_json_response()
    assert isinstance(response, Response), f"Expected Response, got {type(response)}"
    assert response.data == {'test': 'data'}, f"Expected data to be converted correctly"
    print("✓ JsonResponse converted to DRF Response")
    
    # Test with TemplateResponse (should be converted)
    @ensure_drf_response
    def view_with_template_response():
        template_response = TemplateResponse(
            request=MagicMock(),
            template='test.html',
            context={'test': 'data'}
        )
        # Mock the render method
        template_response.render = MagicMock()
        template_response.status_code = 200
        template_response.content = b'{"test": "data"}'
        return template_response
    
    response = view_with_template_response()
    assert isinstance(response, Response), f"Expected Response, got {type(response)}"
    print("✓ TemplateResponse converted to DRF Response")
    
    # Test with basic HttpResponse (should be converted)
    @ensure_drf_response
    def view_with_http_response():
        return HttpResponse('{"test": "data"}', content_type='application/json')
    
    response = view_with_http_response()
    assert isinstance(response, Response), f"Expected Response, got {type(response)}"
    print("✓ HttpResponse converted to DRF Response")

def test_log_response_type_decorator():
    """Test that the log_response_type decorator logs correctly."""
    print("\nTesting log_response_type decorator...")
    
    @log_response_type
    def view_with_response():
        return Response({'test': 'data'})
    
    with patch('authentication.response_validators.security_logger') as mock_logger:
        response = view_with_response()
        
        # Should log the response type
        mock_logger.debug.assert_called_once()
        log_message = mock_logger.debug.call_args[0][0]
        assert 'Response type for view_with_response' in log_message, f"Expected log message, got: {log_message}"
        
        # Should return the original response
        assert isinstance(response, Response), f"Expected Response, got {type(response)}"
        assert response.data == {'test': 'data'}, f"Expected data to be preserved"
    
    print("✓ Response type logged correctly")

def test_error_handling():
    """Test that decorators handle errors gracefully."""
    print("\nTesting error handling...")
    
    @ensure_drf_response
    def view_that_raises_exception():
        raise ValueError("Test error")
    
    response = view_that_raises_exception()
    assert isinstance(response, Response), f"Expected Response, got {type(response)}"
    assert response.status_code == 500, f"Expected 500 status code, got {response.status_code}"
    assert 'error' in response.data, f"Expected error in response data"
    print("✓ Exceptions handled gracefully")

def main():
    """Run all tests."""
    print("Running response validation tests...\n")
    
    try:
        test_validate_response_type_decorator()
        test_ensure_drf_response_decorator()
        test_log_response_type_decorator()
        test_error_handling()
        
        print("\n✅ All tests passed! Response validation decorators are working correctly.")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)