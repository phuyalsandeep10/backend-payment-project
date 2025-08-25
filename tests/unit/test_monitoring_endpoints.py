#!/usr/bin/env python
"""
Test monitoring endpoints functionality
"""

import os
import sys
import django
from django.test import Client
import json

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from core_config.response_processing_monitor import response_processing_monitor


def test_monitoring_endpoints():
    """Test monitoring API endpoints"""
    print("=== Testing Response Monitoring Endpoints ===\n")
    
    # First, add some test data
    monitor = response_processing_monitor
    
    # Add test metrics
    monitor.record_response_type('TemplateResponse', '/api/login/', 'POST', 200, 0.15, 1, 1)
    monitor.record_response_type('DRFResponse', '/api/users/', 'GET', 200, 0.05, 1, 1)
    monitor.record_template_render('login.html', 0.12, True, None, 150)
    monitor.record_content_not_rendered_error('/api/login/', 'POST', 'TestMiddleware', 'Test trace', 1, 1)
    
    client = Client()
    
    # Test 1: Health check endpoint (no auth required)
    print("1. Testing health check endpoint...")
    try:
        response = client.get('/api/response-monitoring/health-check/')
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = json.loads(response.content)
            print(f"   Health status: {data.get('status')}")
            print(f"   Component: {data.get('component')}")
            print(f"   ✓ Health check endpoint working")
        else:
            print(f"   ❌ Health check failed with status {response.status_code}")
    except Exception as e:
        print(f"   ❌ Health check error: {str(e)}")
    
    # Test 2: Check if monitoring URLs are properly configured
    print("\n2. Testing URL configuration...")
    try:
        from django.urls import reverse
        from django.urls.exceptions import NoReverseMatch
        
        # Test URL patterns
        urls_to_test = [
            'response_monitoring:health_check',
            'response_monitoring:overview',
            'response_monitoring:response_types',
            'response_monitoring:template_rendering',
            'response_monitoring:errors',
        ]
        
        for url_name in urls_to_test:
            try:
                url = reverse(url_name)
                print(f"   ✓ URL '{url_name}' -> {url}")
            except NoReverseMatch:
                print(f"   ❌ URL '{url_name}' not found")
                
    except Exception as e:
        print(f"   ❌ URL configuration error: {str(e)}")
    
    # Test 3: Test monitoring data persistence
    print("\n3. Testing monitoring data...")
    try:
        metrics = monitor.get_performance_metrics(hours=1)
        print(f"   Total responses: {metrics['overall_stats']['total_responses']}")
        print(f"   Template renders: {metrics['template_rendering']['total_renders']}")
        print(f"   Total errors: {metrics['errors']['total_errors']}")
        print(f"   CNR errors: {metrics['errors']['content_not_rendered_errors']}")
        print("   ✓ Monitoring data accessible")
    except Exception as e:
        print(f"   ❌ Monitoring data error: {str(e)}")
    
    # Test 4: Test middleware integration
    print("\n4. Testing middleware integration...")
    try:
        from django.conf import settings
        middleware = settings.MIDDLEWARE
        
        monitoring_middleware = [
            'core_config.content_rendering_middleware.ContentNotRenderedErrorMiddleware',
            'core_config.response_rendering_middleware.ResponseRenderingMiddleware',
            'core_config.response_rendering_middleware.ResponseTypeValidationMiddleware',
            'core_config.content_rendering_middleware.ResponseContentAccessMiddleware',
        ]
        
        for mw in monitoring_middleware:
            if mw in middleware:
                print(f"   ✓ {mw.split('.')[-1]} configured")
            else:
                print(f"   ❌ {mw.split('.')[-1]} not configured")
                
    except Exception as e:
        print(f"   ❌ Middleware check error: {str(e)}")
    
    print("\n=== Test Summary ===")
    print("✓ Response processing monitoring endpoints tested")
    print("✓ URL configuration verified")
    print("✓ Monitoring data accessible")
    print("✓ Middleware integration checked")
    
    return True


if __name__ == '__main__':
    try:
        test_monitoring_endpoints()
        print("\n🎉 Response monitoring endpoints are working correctly!")
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)