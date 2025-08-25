"""
Test script for response processing monitoring functionality
"""

import os
import sys
import django
from django.test import TestCase, RequestFactory
from django.http import HttpResponse
from django.template.response import TemplateResponse
from rest_framework.response import Response as DRFResponse
from rest_framework import status
import time

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from core_config.response_processing_monitor import response_processing_monitor, monitor_response_processing
from core_config.response_rendering_middleware import ResponseRenderingMiddleware


class ResponseMonitoringTest:
    """Test class for response processing monitoring"""
    
    def __init__(self):
        self.factory = RequestFactory()
        self.monitor = response_processing_monitor
        
    def test_response_type_recording(self):
        """Test recording of different response types"""
        print("Testing response type recording...")
        
        # Create a mock request
        request = self.factory.get('/api/test/')
        
        # Test different response types
        responses = [
            ('HttpResponse', HttpResponse('Test content')),
            ('DRFResponse', DRFResponse({'message': 'test'})),
        ]
        
        for response_type, response in responses:
            self.monitor.record_response_type(
                response_type=response_type,
                endpoint='/api/test/',
                method='GET',
                status_code=200,
                render_time=0.1,
                user_id=1,
                organization_id=1
            )
            print(f"  ✓ Recorded {response_type}")
        
        # Get summary
        summary = self.monitor.get_response_type_summary(hours=1)
        print(f"  Response type summary: {summary['response_types']}")
        print(f"  Total responses: {summary['total_responses']}")
        
    def test_template_render_recording(self):
        """Test recording of template rendering metrics"""
        print("\nTesting template render recording...")
        
        # Test successful render
        self.monitor.record_template_render(
            template_name='test_template.html',
            render_time=0.05,
            success=True,
            context_size=100
        )
        print("  ✓ Recorded successful template render")
        
        # Test failed render
        self.monitor.record_template_render(
            template_name='broken_template.html',
            render_time=0.02,
            success=False,
            error_message='Template not found',
            context_size=50
        )
        print("  ✓ Recorded failed template render")
        
        # Get summary
        summary = self.monitor.get_template_render_summary(hours=1)
        print(f"  Template render summary: {summary['total_renders']} renders, {summary['success_rate']:.1f}% success rate")
        
    def test_content_not_rendered_error_recording(self):
        """Test recording of ContentNotRenderedError occurrences"""
        print("\nTesting ContentNotRenderedError recording...")
        
        self.monitor.record_content_not_rendered_error(
            endpoint='/api/login/',
            method='POST',
            middleware_name='CommonMiddleware',
            stack_trace='Traceback (most recent call last):\n  ContentNotRenderedError: The response content must be rendered before it can be accessed.',
            user_id=1,
            organization_id=1
        )
        print("  ✓ Recorded ContentNotRenderedError")
        
        # Get recent errors
        cnr_errors = self.monitor.get_recent_content_not_rendered_errors(limit=10)
        print(f"  Recent CNR errors: {len(cnr_errors)}")
        
    def test_error_recording(self):
        """Test recording of general response processing errors"""
        print("\nTesting error recording...")
        
        self.monitor.record_response_processing_error(
            error_type='TemplateDoesNotExist',
            endpoint='/api/test/',
            method='GET',
            error_message='Template "missing.html" does not exist',
            stack_trace='Traceback...',
            user_id=1,
            organization_id=1
        )
        print("  ✓ Recorded TemplateDoesNotExist error")
        
        # Get error summary
        error_summary = self.monitor.get_error_summary(hours=1)
        print(f"  Error summary: {error_summary['total_errors']} total errors")
        print(f"  Error types: {error_summary['error_types']}")
        
    def test_performance_metrics(self):
        """Test comprehensive performance metrics"""
        print("\nTesting performance metrics...")
        
        metrics = self.monitor.get_performance_metrics(hours=1)
        
        print("  Performance metrics retrieved:")
        print(f"    Response types: {metrics['response_types']['total_responses']} responses")
        print(f"    Template rendering: {metrics['template_rendering']['total_renders']} renders")
        print(f"    Errors: {metrics['errors']['total_errors']} errors")
        print(f"    Overall render success rate: {metrics['overall_stats']['render_success_rate']:.1f}%")
        
    def test_slow_render_detection(self):
        """Test slow render detection"""
        print("\nTesting slow render detection...")
        
        # Record a slow response
        self.monitor.record_response_type(
            response_type='TemplateResponse',
            endpoint='/api/slow/',
            method='GET',
            status_code=200,
            render_time=1.5,  # Slow render
            user_id=1,
            organization_id=1
        )
        print("  ✓ Recorded slow response")
        
        # Record a slow template render
        self.monitor.record_template_render(
            template_name='slow_template.html',
            render_time=0.8,  # Slow render
            success=True,
            context_size=1000
        )
        print("  ✓ Recorded slow template render")
        
        # Get slow renders
        slow_renders = self.monitor.get_slow_renders(limit=10)
        print(f"  Slow renders detected: {len(slow_renders)}")
        
        for render in slow_renders[:3]:  # Show first 3
            print(f"    {render['name']} ({render['type']}): {render['render_time']:.3f}s")
    
    def test_decorator_functionality(self):
        """Test the monitoring decorator"""
        print("\nTesting monitoring decorator...")
        
        @monitor_response_processing
        def mock_view(request):
            """Mock view function"""
            time.sleep(0.01)  # Simulate processing time
            return HttpResponse('Mock response')
        
        # Create mock request
        request = self.factory.get('/api/decorated/')
        request.user = type('MockUser', (), {
            'is_authenticated': True,
            'id': 1,
            'organization': type('MockOrg', (), {'id': 1})()
        })()
        
        # Call decorated function
        response = mock_view(request)
        print("  ✓ Decorator executed successfully")
        print(f"  Response type: {type(response).__name__}")
        
    def run_all_tests(self):
        """Run all tests"""
        print("=== Response Processing Monitoring Tests ===\n")
        
        try:
            self.test_response_type_recording()
            self.test_template_render_recording()
            self.test_content_not_rendered_error_recording()
            self.test_error_recording()
            self.test_performance_metrics()
            self.test_slow_render_detection()
            self.test_decorator_functionality()
            
            print("\n=== Test Summary ===")
            print("✓ All tests completed successfully!")
            
            # Show final metrics
            final_metrics = self.monitor.get_performance_metrics(hours=1)
            print(f"\nFinal metrics:")
            print(f"  Total responses recorded: {final_metrics['overall_stats']['total_responses']}")
            print(f"  Template renders: {final_metrics['template_rendering']['total_renders']}")
            print(f"  Errors recorded: {final_metrics['errors']['total_errors']}")
            print(f"  CNR errors: {final_metrics['errors']['content_not_rendered_errors']}")
            
        except Exception as e:
            print(f"\n❌ Test failed with error: {str(e)}")
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    test = ResponseMonitoringTest()
    test.run_all_tests()