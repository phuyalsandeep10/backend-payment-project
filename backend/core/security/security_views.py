"""
Security Dashboard API Views
Provides endpoints for security monitoring and management
"""

from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from apps.authentication.models import SecurityEvent
from core_config.security_monitoring import SecurityDashboard
from core_config.error_handling import security_event_logger

# Security dashboard response schema
dashboard_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
        'data': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'total_events': openapi.Schema(type=openapi.TYPE_INTEGER),
                'critical_events': openapi.Schema(type=openapi.TYPE_INTEGER),
                'high_risk_events': openapi.Schema(type=openapi.TYPE_INTEGER),
                'blocked_events': openapi.Schema(type=openapi.TYPE_INTEGER),
                'uninvestigated_events': openapi.Schema(type=openapi.TYPE_INTEGER),
                'events_by_type': openapi.Schema(type=openapi.TYPE_OBJECT),
                'events_by_severity': openapi.Schema(type=openapi.TYPE_OBJECT),
                'top_ips': openapi.Schema(type=openapi.TYPE_ARRAY),
                'top_users': openapi.Schema(type=openapi.TYPE_ARRAY),
            }
        )
    }
)

def is_security_admin(user):
    """Check if user has security admin permissions"""
    return (
        user.is_authenticated and 
        (user.is_superuser or 
         (hasattr(user, 'role') and user.role and 
          any(keyword in user.role.name.lower() for keyword in ['admin', 'security'])))
    )

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('days', openapi.IN_QUERY, description="Number of days to analyze", type=openapi.TYPE_INTEGER, default=7)
    ],
    responses={
        200: dashboard_response_schema,
        403: 'Access denied - Security admin required'
    },
    tags=['Security Dashboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_dashboard_data(request):
    """
    Get security dashboard data
    """
    if not is_security_admin(request.user):
        return Response({
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'Security admin access required'
            }
        }, status=status.HTTP_403_FORBIDDEN)
    
    days = int(request.GET.get('days', 7))
    
    try:
        dashboard_data = SecurityDashboard.get_dashboard_data(days)
        
        # Log dashboard access
        security_event_logger.log_data_access(
            request=request,
            resource='security_dashboard',
            action='view'
        )
        
        return Response({
            'success': True,
            'data': dashboard_data,
            'period_days': days
        })
        
    except Exception as e:
        return Response({
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to retrieve dashboard data'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='get',
    responses={
        200: 'Real-time threat data',
        403: 'Access denied'
    },
    tags=['Security Dashboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def real_time_threats(request):
    """
    Get real-time threat indicators
    """
    if not is_security_admin(request.user):
        return Response({
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'Security admin access required'
            }
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        threats = SecurityDashboard.get_real_time_threats()
        
        return Response({
            'success': True,
            'threats': threats,
            'count': len(threats)
        })
        
    except Exception as e:
        return Response({
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to retrieve threat data'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('days', openapi.IN_QUERY, description="Number of days to analyze", type=openapi.TYPE_INTEGER, default=7),
        openapi.Parameter('limit', openapi.IN_QUERY, description="Number of IPs to return", type=openapi.TYPE_INTEGER, default=10)
    ],
    responses={
        200: 'Top risk IP addresses',
        403: 'Access denied'
    },
    tags=['Security Dashboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def top_risk_ips(request):
    """
    Get top risk IP addresses
    """
    if not is_security_admin(request.user):
        return Response({
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'Security admin access required'
            }
        }, status=status.HTTP_403_FORBIDDEN)
    
    days = int(request.GET.get('days', 7))
    limit = int(request.GET.get('limit', 10))
    
    try:
        top_ips = SecurityDashboard.get_top_risk_ips(days, limit)
        
        return Response({
            'success': True,
            'top_ips': top_ips,
            'period_days': days
        })
        
    except Exception as e:
        return Response({
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to retrieve IP risk data'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('days', openapi.IN_QUERY, description="Number of days to analyze", type=openapi.TYPE_INTEGER, default=30)
    ],
    responses={
        200: 'Security trends data',
        403: 'Access denied'
    },
    tags=['Security Dashboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_trends(request):
    """
    Get security trends over time
    """
    if not is_security_admin(request.user):
        return Response({
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'Security admin access required'
            }
        }, status=status.HTTP_403_FORBIDDEN)
    
    days = int(request.GET.get('days', 30))
    
    try:
        trends = SecurityDashboard.get_security_trends(days)
        
        return Response({
            'success': True,
            'trends': trends
        })
        
    except Exception as e:
        return Response({
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to retrieve trends data'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='get',
    responses={
        200: 'Investigation queue',
        403: 'Access denied'
    },
    tags=['Security Dashboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def investigation_queue(request):
    """
    Get events requiring investigation
    """
    if not is_security_admin(request.user):
        return Response({
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'Security admin access required'
            }
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        queue = SecurityDashboard.get_investigation_queue()
        
        return Response({
            'success': True,
            'queue': queue,
            'count': len(queue)
        })
        
    except Exception as e:
        return Response({
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to retrieve investigation queue'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['event_id'],
        properties={
            'event_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            'notes': openapi.Schema(type=openapi.TYPE_STRING),
        }
    ),
    responses={
        200: 'Event marked as investigated',
        400: 'Invalid request',
        403: 'Access denied',
        404: 'Event not found'
    },
    tags=['Security Dashboard']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_investigated(request):
    """
    Mark a security event as investigated
    """
    if not is_security_admin(request.user):
        return Response({
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'Security admin access required'
            }
        }, status=status.HTTP_403_FORBIDDEN)
    
    event_id = request.data.get('event_id')
    notes = request.data.get('notes', '')
    
    if not event_id:
        return Response({
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'Event ID is required'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        event = SecurityEvent.objects.get(id=event_id)
        event.mark_investigated(request.user, notes)
        
        # Log the investigation action
        security_event_logger.log_admin_action(
            request=request,
            action='mark_investigated',
            target=f'security_event_{event_id}',
            details={'notes': notes}
        )
        
        return Response({
            'success': True,
            'message': 'Event marked as investigated'
        })
        
    except SecurityEvent.DoesNotExist:
        return Response({
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Security event not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to update event'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('event_id', openapi.IN_PATH, description="Security event ID", type=openapi.TYPE_INTEGER)
    ],
    responses={
        200: 'Security event details',
        403: 'Access denied',
        404: 'Event not found'
    },
    tags=['Security Dashboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_event_detail(request, event_id):
    """
    Get detailed information about a security event
    """
    if not is_security_admin(request.user):
        return Response({
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'Security admin access required'
            }
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        event = SecurityEvent.objects.get(id=event_id)
        
        event_data = {
            'id': event.id,
            'event_type': event.event_type,
            'severity': event.severity,
            'timestamp': event.timestamp,
            'user_email': event.user_email,
            'user_role': event.user_role,
            'ip_address': event.ip_address,
            'user_agent': event.user_agent,
            'request_path': event.request_path,
            'request_method': event.request_method,
            'event_description': event.event_description,
            'event_data': event.event_data,
            'country': event.country,
            'city': event.city,
            'response_status': event.response_status,
            'response_time_ms': event.response_time_ms,
            'correlation_id': event.correlation_id,
            'session_id': event.session_id,
            'risk_score': event.risk_score,
            'is_blocked': event.is_blocked,
            'is_investigated': event.is_investigated,
            'investigated_by': event.investigated_by.email if event.investigated_by else None,
            'investigated_at': event.investigated_at,
            'investigation_notes': event.investigation_notes,
        }
        
        # Log the event access
        security_event_logger.log_data_access(
            request=request,
            resource='security_event',
            action='view',
            record_count=1
        )
        
        return Response({
            'success': True,
            'event': event_data
        })
        
    except SecurityEvent.DoesNotExist:
        return Response({
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Security event not found'
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to retrieve event details'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['ip_address', 'reason'],
        properties={
            'ip_address': openapi.Schema(type=openapi.TYPE_STRING),
            'reason': openapi.Schema(type=openapi.TYPE_STRING),
            'duration_hours': openapi.Schema(type=openapi.TYPE_INTEGER, default=24),
        }
    ),
    responses={
        200: 'IP address blocked',
        400: 'Invalid request',
        403: 'Access denied'
    },
    tags=['Security Dashboard']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def block_ip_address(request):
    """
    Block an IP address for security reasons
    """
    if not is_security_admin(request.user):
        return Response({
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'Security admin access required'
            }
        }, status=status.HTTP_403_FORBIDDEN)
    
    ip_address = request.data.get('ip_address')
    reason = request.data.get('reason')
    duration_hours = request.data.get('duration_hours', 24)
    
    if not ip_address or not reason:
        return Response({
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'IP address and reason are required'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        from core_config.security_monitoring import suspicious_activity_detector
        
        # Flag IP as malicious
        suspicious_activity_detector.flag_ip_as_malicious(ip_address, reason, duration_hours)
        
        # Log the admin action
        security_event_logger.log_admin_action(
            request=request,
            action='block_ip',
            target=ip_address,
            details={
                'reason': reason,
                'duration_hours': duration_hours
            }
        )
        
        return Response({
            'success': True,
            'message': f'IP address {ip_address} blocked for {duration_hours} hours'
        })
        
    except Exception as e:
        return Response({
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to block IP address'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='post',
    responses={
        200: 'Cleanup completed',
        403: 'Access denied'
    },
    tags=['Security Dashboard']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cleanup_old_events(request):
    """
    Clean up old security events (admin only)
    """
    if not request.user.is_superuser:
        return Response({
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'Superuser access required'
            }
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        deleted_count = SecurityEvent.cleanup_old_events()
        
        # Log the cleanup action
        security_event_logger.log_admin_action(
            request=request,
            action='cleanup_security_events',
            target='security_events',
            details={'deleted_count': deleted_count}
        )
        
        return Response({
            'success': True,
            'message': f'Cleaned up {deleted_count} old security events'
        })
        
    except Exception as e:
        return Response({
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to cleanup events'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)