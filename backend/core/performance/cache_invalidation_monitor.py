"""
Cache Invalidation Monitor - Task 4.1.2

Monitoring and analytics for cache invalidation performance.
Tracks efficiency gains and identifies optimization opportunities.
"""

from django.http import JsonResponse
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, timedelta
from typing import Dict, Any, List
import json
import logging

from .cache_invalidation_optimizer import cache_invalidation_manager, SmartCacheInvalidation

logger = logging.getLogger(__name__)


@staff_member_required
@csrf_exempt
def invalidation_metrics_api(request):
    """
    API endpoint for cache invalidation metrics
    Task 4.1.2: Invalidation performance monitoring
    """
    
    if request.method == 'GET':
        try:
            metrics = cache_invalidation_manager.get_invalidation_metrics()
            queue_status = cache_invalidation_manager.get_queue_status()
            
            # Calculate efficiency metrics
            efficiency_data = _calculate_efficiency_metrics(metrics)
            
            response_data = {
                'success': True,
                'data': {
                    'metrics': {
                        'total_invalidations': metrics.total_invalidations,
                        'batch_invalidations': metrics.batch_invalidations,
                        'individual_invalidations': metrics.individual_invalidations,
                        'failed_invalidations': metrics.failed_invalidations,
                        'total_keys_invalidated': metrics.total_keys_invalidated,
                        'avg_batch_time': metrics.avg_batch_time,
                        'avg_individual_time': metrics.avg_individual_time,
                        'total_time_saved': metrics.total_time_saved
                    },
                    'queue_status': queue_status,
                    'efficiency': efficiency_data
                },
                'timestamp': datetime.now().isoformat()
            }
            
            return JsonResponse(response_data)
            
        except Exception as e:
            logger.error(f"Error getting invalidation metrics: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@staff_member_required
@csrf_exempt
def invalidation_control_api(request):
    """
    API endpoint for controlling cache invalidation
    Task 4.1.2: Invalidation control interface
    """
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
            
            if action == 'clear_queues':
                cache_invalidation_manager.clear_queues()
                message = "All invalidation queues cleared"
                
            elif action == 'optimize_org':
                org_id = data.get('organization_id')
                batch_size = data.get('batch_size', 100)
                
                if not org_id:
                    return JsonResponse({
                        'success': False,
                        'error': 'organization_id is required'
                    }, status=400)
                
                cache_invalidation_manager.optimize_organization_settings(org_id, batch_size)
                message = f"Optimized invalidation settings for organization {org_id}"
                
            elif action == 'invalidate_org':
                org_id = data.get('organization_id')
                selective = data.get('selective', True)
                
                if not org_id:
                    return JsonResponse({
                        'success': False,
                        'error': 'organization_id is required'
                    }, status=400)
                
                result = cache_invalidation_manager.invalidate_organization_cache(org_id, selective)
                
                if result['success']:
                    message = f"Invalidated organization {org_id} cache: {result['keys_invalidated']} keys"
                else:
                    return JsonResponse({
                        'success': False,
                        'error': f"Invalidation failed: {result['error']}"
                    }, status=500)
                    
            elif action == 'test_invalidation':
                keys = data.get('keys', [])
                patterns = data.get('patterns', [])
                
                if not keys and not patterns:
                    return JsonResponse({
                        'success': False,
                        'error': 'keys or patterns required'
                    }, status=400)
                
                result = cache_invalidation_manager.invalidate_immediate(
                    keys=keys,
                    patterns=patterns
                )
                
                return JsonResponse({
                    'success': result['success'],
                    'message': f"Test invalidation completed: {result.get('keys_invalidated', 0)} keys",
                    'result': result
                })
                
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid action. Use: clear_queues, optimize_org, invalidate_org, or test_invalidation'
                }, status=400)
            
            return JsonResponse({
                'success': True,
                'message': message
            })
            
        except Exception as e:
            logger.error(f"Error controlling cache invalidation: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@staff_member_required
def invalidation_analytics_api(request):
    """
    API endpoint for cache invalidation analytics
    Task 4.1.2: Performance analytics
    """
    
    if request.method == 'GET':
        try:
            period = request.GET.get('period', 'hour')  # hour, day, week
            
            # Get metrics
            metrics = cache_invalidation_manager.get_invalidation_metrics()
            queue_status = cache_invalidation_manager.get_queue_status()
            
            # Calculate analytics based on period
            analytics_data = _calculate_invalidation_analytics(metrics, period)
            
            response_data = {
                'success': True,
                'data': {
                    'period': period,
                    'analytics': analytics_data,
                    'current_metrics': {
                        'total_invalidations': metrics.total_invalidations,
                        'success_rate': _calculate_success_rate(metrics),
                        'efficiency_score': _calculate_efficiency_score(metrics),
                        'avg_batch_size': _calculate_avg_batch_size(metrics),
                        'time_saved_percentage': _calculate_time_saved_percentage(metrics)
                    },
                    'queue_health': _assess_queue_health(queue_status),
                    'recommendations': _generate_invalidation_recommendations(metrics, queue_status)
                },
                'timestamp': datetime.now().isoformat()
            }
            
            return JsonResponse(response_data)
            
        except Exception as e:
            logger.error(f"Error getting invalidation analytics: {e}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


def _calculate_efficiency_metrics(metrics) -> Dict[str, float]:
    """Calculate cache invalidation efficiency metrics"""
    
    total_ops = metrics.total_invalidations
    if total_ops == 0:
        return {
            'success_rate': 0.0,
            'batch_efficiency': 0.0,
            'time_efficiency': 0.0,
            'overall_efficiency': 0.0
        }
    
    success_rate = ((total_ops - metrics.failed_invalidations) / total_ops) * 100
    
    # Batch efficiency - percentage of operations that were batched
    batch_efficiency = (metrics.batch_invalidations / total_ops) * 100 if total_ops > 0 else 0
    
    # Time efficiency - time saved percentage
    total_estimated_time = metrics.total_keys_invalidated * 0.001  # 1ms per key
    time_efficiency = (metrics.total_time_saved / max(total_estimated_time, 0.001)) * 100
    
    # Overall efficiency score
    overall_efficiency = (success_rate + batch_efficiency + min(time_efficiency, 100)) / 3
    
    return {
        'success_rate': success_rate,
        'batch_efficiency': batch_efficiency,
        'time_efficiency': min(time_efficiency, 100),  # Cap at 100%
        'overall_efficiency': overall_efficiency
    }


def _calculate_invalidation_analytics(metrics, period: str) -> Dict[str, Any]:
    """Calculate invalidation analytics for specified period"""
    
    # This would typically pull from a time-series database
    # For now, provide current metrics with period context
    
    analytics = {
        'invalidations_per_period': 0,
        'keys_per_period': 0,
        'avg_response_time': 0,
        'error_rate': 0,
        'batch_usage': 0
    }
    
    if metrics.total_invalidations > 0:
        # Estimate based on current metrics (in real implementation, use historical data)
        period_multiplier = {'hour': 1, 'day': 24, 'week': 168}.get(period, 1)
        
        analytics.update({
            'invalidations_per_period': metrics.total_invalidations / period_multiplier,
            'keys_per_period': metrics.total_keys_invalidated / period_multiplier,
            'avg_response_time': (metrics.avg_batch_time + metrics.avg_individual_time) / 2,
            'error_rate': (metrics.failed_invalidations / metrics.total_invalidations) * 100,
            'batch_usage': (metrics.batch_invalidations / metrics.total_invalidations) * 100
        })
    
    return analytics


def _calculate_success_rate(metrics) -> float:
    """Calculate invalidation success rate"""
    total = metrics.total_invalidations
    if total == 0:
        return 100.0
    
    return ((total - metrics.failed_invalidations) / total) * 100


def _calculate_efficiency_score(metrics) -> float:
    """Calculate overall efficiency score"""
    
    if metrics.total_invalidations == 0:
        return 0.0
    
    # Factors: success rate, batch usage, time savings
    success_rate = _calculate_success_rate(metrics)
    batch_usage = (metrics.batch_invalidations / metrics.total_invalidations) * 100
    
    # Time savings efficiency
    total_estimated_time = metrics.total_keys_invalidated * 0.001
    time_efficiency = min((metrics.total_time_saved / max(total_estimated_time, 0.001)) * 100, 100)
    
    return (success_rate + batch_usage + time_efficiency) / 3


def _calculate_avg_batch_size(metrics) -> float:
    """Calculate average batch size"""
    
    if metrics.batch_invalidations == 0:
        return 0.0
    
    # Estimate average batch size
    batched_keys = metrics.total_keys_invalidated - metrics.individual_invalidations
    return batched_keys / metrics.batch_invalidations if batched_keys > 0 else 0.0


def _calculate_time_saved_percentage(metrics) -> float:
    """Calculate time saved percentage"""
    
    if metrics.total_keys_invalidated == 0:
        return 0.0
    
    total_estimated_time = metrics.total_keys_invalidated * 0.001
    return (metrics.total_time_saved / max(total_estimated_time, 0.001)) * 100


def _assess_queue_health(queue_status: Dict[str, int]) -> Dict[str, Any]:
    """Assess queue health status"""
    
    total_queued = queue_status['total_queued']
    
    if total_queued == 0:
        status = 'healthy'
        message = 'No queued invalidations'
    elif total_queued < 100:
        status = 'healthy'
        message = 'Normal queue levels'
    elif total_queued < 500:
        status = 'warning'
        message = 'Elevated queue levels'
    else:
        status = 'critical'
        message = 'High queue levels - potential bottleneck'
    
    return {
        'status': status,
        'message': message,
        'total_queued': total_queued,
        'priority_distribution': {
            'high': queue_status['high_priority'],
            'medium': queue_status['medium_priority'],
            'low': queue_status['low_priority']
        }
    }


def _generate_invalidation_recommendations(metrics, queue_status: Dict[str, int]) -> List[str]:
    """Generate performance recommendations"""
    
    recommendations = []
    
    # Success rate recommendations
    success_rate = _calculate_success_rate(metrics)
    if success_rate < 95:
        recommendations.append(
            f"Success rate is {success_rate:.1f}% - investigate failed invalidations"
        )
    
    # Batch usage recommendations
    if metrics.total_invalidations > 0:
        batch_rate = (metrics.batch_invalidations / metrics.total_invalidations) * 100
        if batch_rate < 50:
            recommendations.append(
                f"Only {batch_rate:.1f}% of invalidations use batching - consider increasing batch sizes"
            )
    
    # Queue health recommendations
    total_queued = queue_status['total_queued']
    if total_queued > 500:
        recommendations.append(
            f"High queue levels ({total_queued} items) - consider increasing processing capacity"
        )
    elif total_queued > 100:
        recommendations.append(
            f"Elevated queue levels ({total_queued} items) - monitor closely"
        )
    
    # Time efficiency recommendations
    time_efficiency = _calculate_time_saved_percentage(metrics)
    if time_efficiency < 20:
        recommendations.append(
            "Low time efficiency - consider optimizing batch sizes and patterns"
        )
    
    # Response time recommendations
    if metrics.avg_batch_time > 0.1:  # 100ms
        recommendations.append(
            f"Batch operations averaging {metrics.avg_batch_time:.3f}s - consider reducing batch sizes"
        )
    
    if not recommendations:
        recommendations.append("Cache invalidation is performing optimally")
    
    return recommendations
