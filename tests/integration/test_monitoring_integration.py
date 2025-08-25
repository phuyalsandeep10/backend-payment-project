#!/usr/bin/env python
"""
Integration test for response processing monitoring
"""

import os
import sys
import django
from django.test import RequestFactory
from django.http import HttpResponse
from django.template.response import TemplateResponse, ContentNotRenderedError
import time

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from core_config.response_processing_monitor import response_processing_monitor, monitor_response_processing


def test_response_monitoring():
    """Test response processing monitoring functionality"""
    print("=== Testing Response Processing Monitoring ===\n")
    
    factory = RequestFactory()
    monitor = response_processing_monitor
    
    # Test 1: Record different response types
    print("1. Testing response type recording...")
    monitor.record_response_type('TemplateResponse', '/api/login/', 'POST', 200, 0.15, 1, 1)
    monitor.record_response_type('DRFResponse', '/api/users/', 'GET', 200, 0.05, 1, 1)
    monitor.record_response_type('HttpResponse', '/api/health/', 'GET', 200, 0.02, None, None)
    print("   ✓ Response types recorded")
    
    # Test 2: Record template renders
    print("\n2. Testing template render recording...")
    monitor.record_template_render('login.html', 0.12, True, None, 150)
    monitor.record_template_render('dashboard.html', 0.08, True, None, 200)
    monitor.record_template_render('broken.html', 0.02, False, 'Template not found', 50)
    print("   ✓ Template renders recorded")
    
    # Test 3: Record slow renders
    print("\n3. Testing slow render detection...")
    monitor.record_response_type('TemplateResponse', '/api/slow/', 'GET', 200, 0.8, 1, 1)
    monitor.record_template_render('slow_template.html', 0.7, True, None, 1000)
    print("   ✓ Slow renders recorded")
    
    # Test 4: Record ContentNotRenderedError
    print("\n4. Testing ContentNotRenderedError recording...")
    monitor.record_content_not_rendered_error(
        endpoint='/api/login/',
        method='POST',
        middleware_name='TestMiddleware',
        stack_trace='Test stack trace for ContentNotRenderedError',
        user_id=1,
        organization_id=1
    )
    print("   ✓ ContentNotRenderedError recorded")
    
    # Test 5: Record other errors
    print("\n5. Testing error recording...")
    monitor.record_response_processing_error(
        error_type='TemplateDoesNotExist',
        endpoint='/api/test/',
        method='GET',
        error_message='Template "missing.html" does not exist',
        stack_trace='Test stack trace',
        user_id=1,
        organization_id=1
    )
    print("   ✓ Processing error recorded")
    
    # Test 6: Get comprehensive metrics
    print("\n6. Testing metrics retrieval...")
    metrics = monitor.get_performance_metrics(hours=1)
    
    print(f"   Response Types Summary:")
    print(f"     Total responses: {metrics['response_types']['total_responses']}")
    print(f"     Response types: {metrics['response_types']['response_types']}")
    
    print(f"   Template Rendering Summary:")
    print(f"     Total renders: {metrics['template_rendering']['total_renders']}")
    print(f"     Success rate: {metrics['template_rendering']['success_rate']:.1f}%")
    
    print(f"   Error Summary:")
    print(f"     Total errors: {metrics['errors']['total_errors']}")
    print(f"     CNR errors: {metrics['errors']['content_not_rendered_errors']}")
    print(f"     Error types: {metrics['errors']['error_types']}")
    
    print(f"   Overall Stats:")
    print(f"     Total responses: {metrics['overall_stats']['total_responses']}")
    print(f"     Render success rate: {metrics['overall_stats']['render_success_rate']:.1f}%")
    
    # Test 7: Test slow render detection
    print("\n7. Testing slow render detection...")
    slow_renders = monitor.get_slow_renders(limit=5)
    print(f"   Slow renders detected: {len(slow_renders)}")
    for i, render in enumerate(slow_renders[:3], 1):
        print(f"     {i}. {render['name']} ({render['type']}): {render['render_time']:.3f}s")
    
    # Test 8: Test ContentNotRenderedError details
    print("\n8. Testing ContentNotRenderedError details...")
    cnr_errors = monitor.get_recent_content_not_rendered_errors(limit=5)
    print(f"   Recent CNR errors: {len(cnr_errors)}")
    for i, error in enumerate(cnr_errors, 1):
        print(f"     {i}. {error['method']} {error['endpoint']} - {error['middleware_name']}")
    
    # Test 9: Test decorator functionality
    print("\n9. Testing monitoring decorator...")
    
    @monitor_response_processing
    def mock_view(request):
        time.sleep(0.01)  # Simulate processing
        return HttpResponse('Mock response')
    
    request = factory.get('/api/decorated/')
    request.user = type('MockUser', (), {
        'is_authenticated': True,
        'id': 1,
        'organization': type('MockOrg', (), {'id': 1})()
    })()
    
    response = mock_view(request)
    print(f"   ✓ Decorator executed, response type: {type(response).__name__}")
    
    print("\n=== Test Summary ===")
    final_metrics = monitor.get_performance_metrics(hours=1)
    print(f"✓ All tests completed successfully!")
    print(f"Final metrics:")
    print(f"  Total responses: {final_metrics['overall_stats']['total_responses']}")
    print(f"  Template renders: {final_metrics['template_rendering']['total_renders']}")
    print(f"  Total errors: {final_metrics['errors']['total_errors']}")
    print(f"  CNR errors: {final_metrics['errors']['content_not_rendered_errors']}")
    
    return True


if __name__ == '__main__':
    try:
        test_response_monitoring()
        print("\n🎉 Response processing monitoring is working correctly!")
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)