#!/usr/bin/env python
"""
Test script to verify that the organization null fix works properly
"""

import os
import sys
import django
from django.test import RequestFactory
from django.contrib.auth import get_user_model
from django.http import HttpResponse

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from core_config.response_rendering_middleware import ResponseRenderingMiddleware

def test_null_organization_handling():
    """Test that middleware handles users with null organization"""
    
    # Create a mock request factory
    factory = RequestFactory()
    request = factory.get('/api/test/')
    
    # Create a user without organization
    User = get_user_model()
    user = User(id=1, email='test@example.com', organization=None)
    user.is_authenticated = True
    request.user = user
    
    # Create a simple response
    response = HttpResponse('{"test": "data"}', content_type='application/json')
    
    # Create middleware instance
    def dummy_get_response(request):
        return response
    
    middleware = ResponseRenderingMiddleware(dummy_get_response)
    
    try:
        # This should not raise an AttributeError
        processed_response = middleware.process_response(request, response)
        print("✅ SUCCESS: Middleware handled null organization without error")
        return True
    except AttributeError as e:
        if "'NoneType' object has no attribute 'id'" in str(e):
            print(f"❌ FAILED: AttributeError still occurs: {e}")
            return False
        else:
            print(f"❌ FAILED: Unexpected AttributeError: {e}")
            return False
    except Exception as e:
        print(f"❌ FAILED: Unexpected error: {e}")
        return False

if __name__ == '__main__':
    print("Testing organization null handling fix...")
    success = test_null_organization_handling()
    sys.exit(0 if success else 1)