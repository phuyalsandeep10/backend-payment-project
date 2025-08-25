"""
Response Processing Monitoring Views
API endpoints for response processing monitoring and metrics
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views import View
from django.utils import timezone
from datetime import timedelta
import json
import logging

from .response_processing_monitor import response_processing_monitor
from core_config.utils.decorators import require_organization_access, require_admin_access

logger = logging.getLogger(__name__)

class ResponseMonitoringView(View):
    """Base view for response processing monitoring endpoints"""
    
    @method_decorator(login_required)
    @method_decorator(require_organization_access)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

@method_decorator(csrf_exempt, name='dispatch')
class ResponseTypeMetricsView(ResponseMonitoringView):
    """Get response type distribution and performance metrics"""
    
    def get(self, request):
        try:
            # Get time period from query params (default 1 hour)
            hours = int(request.GET.get('hours', 1))
            hours = min(hours, 24)  # Limit to 24 hours max
            
            # Get response type summary
            summary = response_processing_monitor.get_response_type_summary(hours=hours)
            
            return JsonResponse({
                'success': True,
                'data': summary
            })
            
        except Exception as e:
            logger.error(f"Error getting response type metrics: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve response type metrics'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class TemplateRenderMetricsView(ResponseMonitoringView):
    """Get template rendering performance metrics"""
    
    def get(self, request):
        try:
            hours = int(request.GET.get('hours', 1))
            hours = min(hours, 24)  # Limit to 24 hours max
            
            # Get template render summary
            summary = response_processing_monitor.get_template_render_summary(hours=hours)
            
            return JsonResponse({
                'success': True,
                'data': summary
            })
            
        except Exception as e:
            logger.error(f"Error getting template render metrics: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve template render metrics'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class ResponseErrorMetricsView(ResponseMonitoringView):
    """Get response processing error metrics"""
    
    def get(self, request):
        try:
            hours = int(request.GET.get('hours', 1))
            hours = min(hours, 24)  # Limit to 24 hours max
            
            # Get error summary
            summary = response_processing_monitor.get_error_summary(hours=hours)
            
            return JsonResponse({
                'success': True,
                'data': summary
            })
            
        except Exception as e:
            logger.error(f"Error getting response error metrics: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve response error metrics'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class ContentNotRenderedErrorsView(ResponseMonitoringView):
    """Get ContentNotRenderedError occurrences"""
    
    def get(self, request):
        try:
            limit = int(request.GET.get('limit', 50))
            limit = min(limit, 200)  # Limit to 200 max
            
            # Get recent ContentNotRenderedError occurrences
            cnr_errors = response_processing_monitor.get_recent_content_not_rendered_errors(limit=limit)
            
            # Calculate error frequency
            if cnr_errors:
                # Group by hour for frequency analysis
                hourly_counts = {}
                for error in cnr_errors:
                    error_time = error['timestamp'][:13]  # YYYY-MM-DDTHH
                    hourly_counts[error_time] = hourly_counts.get(error_time, 0) + 1
                
                # Get most problematic endpoints
                endpoint_counts = {}
                for error in cnr_errors:
                    endpoint = f"{error['method']} {error['endpoint']}"
                    endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
                
                # Sort endpoints by error count
                top_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            else:
                hourly_counts = {}
                top_endpoints = []
            
            return JsonResponse({
                'success': True,
                'data': {
                    'content_not_rendered_errors': cnr_errors,
                    'total_count': len(cnr_errors),
                    'hourly_frequency': hourly_counts,
                    'top_problematic_endpoints': top_endpoints,
                    'analysis': {
                        'most_recent': cnr_errors[0] if cnr_errors else None,
                        'unique_endpoints': len(set(f"{e['method']} {e['endpoint']}" for e in cnr_errors)),
                        'unique_middleware': len(set(e['middleware_name'] for e in cnr_errors))
                    }
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting ContentNotRenderedError data: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve ContentNotRenderedError data'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class SlowRenderMetricsView(ResponseMonitoringView):
    """Get slow response rendering metrics"""
    
    def get(self, request):
        try:
            limit = int(request.GET.get('limit', 50))
            limit = min(limit, 200)  # Limit to 200 max
            
            # Get slow renders
            slow_renders = response_processing_monitor.get_slow_renders(limit=limit)
            
            # Analyze slow render patterns
            if slow_renders:
                # Group by type
                by_type = {'response': [], 'template': []}
                for render in slow_renders:
                    by_type[render['type']].append(render)
                
                # Calculate averages
                response_renders = by_type['response']
                template_renders = by_type['template']
                
                avg_response_time = sum(r['render_time'] for r in response_renders) / len(response_renders) if response_renders else 0
                avg_template_time = sum(r['render_time'] for r in template_renders) / len(template_renders) if template_renders else 0
                
                analysis = {
                    'total_slow_renders': len(slow_renders),
                    'response_renders': len(response_renders),
                    'template_renders': len(template_renders),
                    'avg_response_render_time': avg_response_time,
                    'avg_template_render_time': avg_template_time,
                    'slowest_render': slow_renders[0] if slow_renders else None
                }
            else:
                analysis = {
                    'total_slow_renders': 0,
                    'response_renders': 0,
                    'template_renders': 0,
                    'avg_response_render_time': 0,
                    'avg_template_render_time': 0,
                    'slowest_render': None
                }
            
            return JsonResponse({
                'success': True,
                'data': {
                    'slow_renders': slow_renders,
                    'analysis': analysis
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting slow render metrics: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve slow render metrics'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class ResponseProcessingOverviewView(ResponseMonitoringView):
    """Get comprehensive response processing overview"""
    
    def get(self, request):
        try:
            hours = int(request.GET.get('hours', 1))
            hours = min(hours, 24)  # Limit to 24 hours max
            
            # Get comprehensive metrics
            metrics = response_processing_monitor.get_performance_metrics(hours=hours)
            
            # Add additional insights
            insights = self._generate_insights(metrics)
            
            return JsonResponse({
                'success': True,
                'data': {
                    'metrics': metrics,
                    'insights': insights,
                    'generated_at': timezone.now().isoformat()
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting response processing overview: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve response processing overview'
            }, status=500)
    
    def _generate_insights(self, metrics: dict) -> dict:
        """Generate insights from metrics data"""
        insights = {
            'health_status': 'healthy',
            'issues': [],
            'recommendations': []
        }
        
        # Check response type distribution
        response_types = metrics['response_types']['response_types']
        total_responses = metrics['response_types']['total_responses']
        
        if total_responses > 0:
            # Check for high template response ratio
            template_ratio = response_types.get('TemplateResponse', 0) / total_responses
            if template_ratio > 0.3:  # More than 30% template responses
                insights['issues'].append(f"High template response ratio: {template_ratio:.1%}")
                insights['recommendations'].append("Consider converting template responses to DRF responses for API endpoints")
                insights['health_status'] = 'warning'
        
        # Check render performance
        render_perf = metrics['response_types']['render_performance']
        if render_perf and render_perf.get('slow_render_rate', 0) > 10:  # More than 10% slow renders
            insights['issues'].append(f"High slow render rate: {render_perf['slow_render_rate']:.1f}%")
            insights['recommendations'].append("Optimize template rendering or response processing")
            insights['health_status'] = 'warning'
        
        # Check error rates
        errors = metrics['errors']
        if errors['content_not_rendered_errors'] > 0:
            insights['issues'].append(f"ContentNotRenderedError occurrences: {errors['content_not_rendered_errors']}")
            insights['recommendations'].append("Review middleware order and response rendering logic")
            insights['health_status'] = 'critical'
        
        # Check template rendering success rate
        template_metrics = metrics['template_rendering']
        if template_metrics['total_renders'] > 0 and template_metrics['success_rate'] < 95:
            insights['issues'].append(f"Low template render success rate: {template_metrics['success_rate']:.1f}%")
            insights['recommendations'].append("Investigate template rendering failures")
            insights['health_status'] = 'warning'
        
        return insights

@method_decorator(csrf_exempt, name='dispatch')
class ResponseProcessingHealthView(ResponseMonitoringView):
    """Get response processing health status"""
    
    def get(self, request):
        try:
            # Get recent metrics (last 5 minutes)
            recent_metrics = response_processing_monitor.get_performance_metrics(hours=0.083)  # 5 minutes
            
            # Determine health status
            health_status = 'healthy'
            alerts = []
            
            # Check for recent ContentNotRenderedErrors
            if recent_metrics['errors']['content_not_rendered_errors'] > 0:
                health_status = 'critical'
                alerts.append({
                    'type': 'critical',
                    'message': f"{recent_metrics['errors']['content_not_rendered_errors']} ContentNotRenderedError(s) in last 5 minutes"
                })
            
            # Check render performance
            render_perf = recent_metrics['response_types']['render_performance']
            if render_perf and render_perf.get('slow_render_rate', 0) > 20:  # More than 20% slow renders
                if health_status == 'healthy':
                    health_status = 'warning'
                alerts.append({
                    'type': 'warning',
                    'message': f"High slow render rate: {render_perf['slow_render_rate']:.1f}%"
                })
            
            # Check template rendering
            template_metrics = recent_metrics['template_rendering']
            if template_metrics['total_renders'] > 0 and template_metrics['success_rate'] < 90:
                if health_status == 'healthy':
                    health_status = 'warning'
                alerts.append({
                    'type': 'warning',
                    'message': f"Low template render success rate: {template_metrics['success_rate']:.1f}%"
                })
            
            return JsonResponse({
                'success': True,
                'data': {
                    'health_status': health_status,
                    'timestamp': timezone.now().isoformat(),
                    'alerts': alerts,
                    'summary': {
                        'total_responses': recent_metrics['response_types']['total_responses'],
                        'content_not_rendered_errors': recent_metrics['errors']['content_not_rendered_errors'],
                        'template_success_rate': template_metrics['success_rate'],
                        'avg_render_time': render_perf.get('avg_render_time', 0) if render_perf else 0
                    }
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting response processing health: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve response processing health'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(require_admin_access, name='dispatch')
class ResponseMonitoringConfigView(ResponseMonitoringView):
    """Configure response processing monitoring (admin only)"""
    
    def get(self, request):
        """Get current configuration"""
        try:
            config = {
                'slow_render_threshold': response_processing_monitor.SLOW_RENDER_THRESHOLD,
                'error_alert_threshold': response_processing_monitor.ERROR_ALERT_THRESHOLD,
                'metrics_retention_hours': response_processing_monitor.METRICS_RETENTION_HOURS
            }
            
            return JsonResponse({
                'success': True,
                'data': config
            })
            
        except Exception as e:
            logger.error(f"Error getting response monitoring config: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve response monitoring configuration'
            }, status=500)
    
    def post(self, request):
        """Update configuration"""
        try:
            data = json.loads(request.body)
            
            # Update thresholds if provided
            if 'slow_render_threshold' in data:
                response_processing_monitor.SLOW_RENDER_THRESHOLD = float(data['slow_render_threshold'])
            
            if 'error_alert_threshold' in data:
                response_processing_monitor.ERROR_ALERT_THRESHOLD = int(data['error_alert_threshold'])
            
            if 'metrics_retention_hours' in data:
                response_processing_monitor.METRICS_RETENTION_HOURS = int(data['metrics_retention_hours'])
            
            logger.info(f"Response monitoring configuration updated by user {request.user.id}")
            
            return JsonResponse({
                'success': True,
                'message': 'Configuration updated successfully'
            })
            
        except Exception as e:
            logger.error(f"Error updating response monitoring config: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to update response monitoring configuration'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(require_admin_access, name='dispatch')
class ResponseMonitoringMaintenanceView(ResponseMonitoringView):
    """Response monitoring maintenance operations (admin only)"""
    
    def post(self, request):
        """Perform maintenance operations"""
        try:
            data = json.loads(request.body)
            operation = data.get('operation')
            
            if operation == 'clear_old_metrics':
                response_processing_monitor.clear_old_metrics()
                message = 'Old response processing metrics cleared successfully'
                
            elif operation == 'reset_counters':
                response_processing_monitor.total_responses = 0
                response_processing_monitor.template_responses = 0
                response_processing_monitor.drf_responses = 0
                response_processing_monitor.http_responses = 0
                response_processing_monitor.render_errors = 0
                response_processing_monitor.content_not_rendered_count = 0
                response_processing_monitor.successful_renders = 0
                response_processing_monitor.failed_renders = 0
                response_processing_monitor.error_counts.clear()
                message = 'Response processing counters reset successfully'
                
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid operation'
                }, status=400)
            
            logger.info(f"Response monitoring maintenance operation '{operation}' performed by user {request.user.id}")
            
            return JsonResponse({
                'success': True,
                'message': message
            })
            
        except Exception as e:
            logger.error(f"Error performing response monitoring maintenance: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to perform maintenance operation'
            }, status=500)

# Health check endpoint for response processing (no authentication required)
@require_http_methods(["GET"])
def response_processing_health_check(request):
    """Response processing health check endpoint"""
    try:
        # Get recent metrics (last minute)
        recent_metrics = response_processing_monitor.get_performance_metrics(hours=0.017)  # 1 minute
        
        # Determine health status
        health_status = 'healthy'
        issues = []
        
        # Check for ContentNotRenderedErrors
        if recent_metrics['errors']['content_not_rendered_errors'] > 0:
            health_status = 'critical'
            issues.append(f"ContentNotRenderedError occurrences: {recent_metrics['errors']['content_not_rendered_errors']}")
        
        # Check render performance
        render_perf = recent_metrics['response_types']['render_performance']
        if render_perf and render_perf.get('slow_render_rate', 0) > 50:  # More than 50% slow renders
            health_status = 'critical' if health_status != 'critical' else health_status
            issues.append(f"Very high slow render rate: {render_perf['slow_render_rate']:.1f}%")
        
        return JsonResponse({
            'status': health_status,
            'timestamp': timezone.now().isoformat(),
            'component': 'response_processing',
            'issues': issues,
            'metrics': {
                'total_responses': recent_metrics['response_types']['total_responses'],
                'content_not_rendered_errors': recent_metrics['errors']['content_not_rendered_errors'],
                'avg_render_time': render_perf.get('avg_render_time', 0) if render_perf else 0,
                'overall_render_success_rate': recent_metrics['overall_stats']['render_success_rate']
            }
        })
        
    except Exception as e:
        logger.error(f"Response processing health check error: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'timestamp': timezone.now().isoformat(),
            'component': 'response_processing',
            'error': 'Health check failed'
        }, status=500)