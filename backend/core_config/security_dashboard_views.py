"""
Security Dashboard Views
API endpoints for security monitoring and audit trail management
"""

from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import Count, Q, Sum
from django.http import JsonResponse
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from .models import SecurityEvent, SecurityAlert, AuditTrail, ComplianceReport
from .security_event_service import security_event_service
from .audit_service import audit_service
from .error_response import StandardErrorResponse

User = get_user_model()


class SecurityDashboardPagination(PageNumberPagination):
    page_size = 25
    page_size_query_param = 'page_size'
    max_page_size = 100


class SecurityDashboardView(APIView):
    """
    Main security dashboard with overview metrics
    """
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]
    
    def get(self, request):
        """
        Get security dashboard overview data
        """
        try:
            days = int(request.GET.get('days', 7))
            dashboard_data = security_event_service.get_security_dashboard_data(days)
            
            return Response({
                'success': True,
                'data': dashboard_data
            })
            
        except Exception as e:
            return StandardErrorResponse.server_error(
                message="Failed to load security dashboard",
                request_id=getattr(request, 'request_id', None)
            ).to_response()


class SecurityEventsView(APIView):
    """
    Security events management
    """
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]
    pagination_class = SecurityDashboardPagination
    
    def get(self, request):
        """
        Get security events with filtering and pagination
        """
        try:
            # Parse query parameters
            event_type = request.GET.get('event_type')
            severity = request.GET.get('severity')
            ip_address = request.GET.get('ip_address')
            user_id = request.GET.get('user_id')
            days = int(request.GET.get('days', 30))
            
            # Build queryset
            queryset = SecurityEvent.objects.all()
            
            # Apply date filter
            if days:
                start_date = timezone.now() - timedelta(days=days)
                queryset = queryset.filter(timestamp__gte=start_date)
            
            # Apply filters
            if event_type:
                queryset = queryset.filter(event_type=event_type)
            if severity:
                queryset = queryset.filter(severity=severity)
            if ip_address:
                queryset = queryset.filter(ip_address=ip_address)
            if user_id:
                queryset = queryset.filter(user_id=user_id)
            
            # Order by timestamp
            queryset = queryset.order_by('-timestamp')
            
            # Paginate
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            
            # Serialize data
            events_data = [event.to_dict() for event in page]
            
            return paginator.get_paginated_response({
                'success': True,
                'events': events_data
            })
            
        except Exception as e:
            return StandardErrorResponse.server_error(
                message="Failed to retrieve security events",
                request_id=getattr(request, 'request_id', None)
            ).to_response()


class SecurityAlertsView(APIView):
    """
    Security alerts management
    """
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]
    pagination_class = SecurityDashboardPagination
    
    def get(self, request):
        """
        Get security alerts
        """
        try:
            # Parse query parameters
            alert_type = request.GET.get('alert_type')
            severity = request.GET.get('severity')
            status_filter = request.GET.get('status', 'open')
            
            # Build queryset
            queryset = SecurityAlert.objects.all()
            
            # Apply filters
            if alert_type:
                queryset = queryset.filter(alert_type=alert_type)
            if severity:
                queryset = queryset.filter(severity=severity)
            if status_filter and status_filter != 'all':
                queryset = queryset.filter(status=status_filter)
            
            # Order by creation date
            queryset = queryset.order_by('-created_at')
            
            # Paginate
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            
            # Serialize data
            alerts_data = []
            for alert in page:
                alert_dict = {
                    'id': str(alert.id),
                    'alert_type': alert.alert_type,
                    'severity': alert.severity,
                    'status': alert.status,
                    'title': alert.title,
                    'description': alert.description,
                    'first_seen': alert.first_seen.isoformat(),
                    'last_seen': alert.last_seen.isoformat(),
                    'created_at': alert.created_at.isoformat(),
                    'event_count': alert.event_count,
                    'risk_score': alert.risk_score,
                    'affected_ips': alert.affected_ips,
                    'assigned_to': alert.assigned_to.username if alert.assigned_to else None
                }
                alerts_data.append(alert_dict)
            
            return paginator.get_paginated_response({
                'success': True,
                'alerts': alerts_data
            })
            
        except Exception as e:
            return StandardErrorResponse.server_error(
                message="Failed to retrieve security alerts",
                request_id=getattr(request, 'request_id', None)
            ).to_response()
    
    def patch(self, request, alert_id):
        """
        Update security alert status
        """
        try:
            alert = SecurityAlert.objects.get(id=alert_id)
            
            # Update allowed fields
            if 'status' in request.data:
                alert.status = request.data['status']
                if alert.status == 'resolved':
                    alert.resolved_at = timezone.now()
            
            if 'assigned_to' in request.data:
                if request.data['assigned_to']:
                    alert.assigned_to = User.objects.get(id=request.data['assigned_to'])
                else:
                    alert.assigned_to = None
            
            alert.save()
            
            # Log the update
            security_event_service.log_user_action(
                action='alert_updated',
                user=request.user,
                target_object=alert,
                request=request,
                details={'alert_id': str(alert.id), 'status': alert.status}
            )
            
            return Response({
                'success': True,
                'message': 'Alert updated successfully'
            })
            
        except SecurityAlert.DoesNotExist:
            return StandardErrorResponse.not_found_error(
                message="Security alert not found",
                request_id=getattr(request, 'request_id', None)
            ).to_response()
        except Exception as e:
            return StandardErrorResponse.server_error(
                message="Failed to update security alert",
                request_id=getattr(request, 'request_id', None)
            ).to_response()


class AuditTrailView(APIView):
    """
    Audit trail management
    """
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]
    pagination_class = SecurityDashboardPagination
    
    def get(self, request):
        """
        Get audit trail records
        """
        try:
            # Parse query parameters
            table_name = request.GET.get('table_name')
            object_id = request.GET.get('object_id')
            action = request.GET.get('action')
            user_id = request.GET.get('user_id')
            is_sensitive = request.GET.get('is_sensitive')
            days = int(request.GET.get('days', 30))
            
            # Build queryset
            queryset = AuditTrail.objects.all()
            
            # Apply date filter
            if days:
                start_date = timezone.now() - timedelta(days=days)
                queryset = queryset.filter(timestamp__gte=start_date)
            
            # Apply filters
            if table_name:
                queryset = queryset.filter(table_name=table_name)
            if object_id:
                queryset = queryset.filter(object_id=object_id)
            if action:
                queryset = queryset.filter(action=action)
            if user_id:
                queryset = queryset.filter(user_id=user_id)
            if is_sensitive is not None:
                queryset = queryset.filter(is_sensitive=is_sensitive.lower() == 'true')
            
            # Order by timestamp
            queryset = queryset.order_by('-timestamp')
            
            # Paginate
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            
            # Serialize data
            audit_data = [audit.to_dict() for audit in page]
            
            return paginator.get_paginated_response({
                'success': True,
                'audit_records': audit_data
            })
            
        except Exception as e:
            return StandardErrorResponse.server_error(
                message="Failed to retrieve audit trail",
                request_id=getattr(request, 'request_id', None)
            ).to_response()


class UserActivityView(APIView):
    """
    User activity audit trail
    """
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = SecurityDashboardPagination
    
    def get(self, request, user_id=None):
        """
        Get user activity audit trail
        """
        try:
            # Determine target user
            if user_id:
                # Admin can view any user's activity
                if not request.user.is_staff:
                    return StandardErrorResponse.permission_error(
                        message="Permission denied to view other user's activity",
                        request_id=getattr(request, 'request_id', None)
                    ).to_response()
                
                try:
                    target_user = User.objects.get(id=user_id)
                except User.DoesNotExist:
                    return StandardErrorResponse.not_found_error(
                        message="User not found",
                        request_id=getattr(request, 'request_id', None)
                    ).to_response()
            else:
                # User viewing their own activity
                target_user = request.user
            
            days = int(request.GET.get('days', 30))
            
            # Get user activity
            activity_records = audit_service.get_user_activity(target_user, days, limit=200)
            
            # Paginate
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(activity_records, request)
            
            # Serialize data
            activity_data = [record.to_dict() for record in page]
            
            return paginator.get_paginated_response({
                'success': True,
                'user_id': target_user.id,
                'username': target_user.username,
                'activity_records': activity_data
            })
            
        except Exception as e:
            return StandardErrorResponse.server_error(
                message="Failed to retrieve user activity",
                request_id=getattr(request, 'request_id', None)
            ).to_response()


class ComplianceReportsView(APIView):
    """
    Compliance reports management
    """
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]
    pagination_class = SecurityDashboardPagination
    
    def get(self, request):
        """
        Get compliance reports
        """
        try:
            report_type = request.GET.get('report_type')
            status_filter = request.GET.get('status')
            
            # Build queryset
            queryset = ComplianceReport.objects.all()
            
            if report_type:
                queryset = queryset.filter(report_type=report_type)
            if status_filter:
                queryset = queryset.filter(status=status_filter)
            
            queryset = queryset.order_by('-created_at')
            
            # Paginate
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            
            # Serialize data
            reports_data = []
            for report in page:
                report_dict = {
                    'id': str(report.id),
                    'report_type': report.report_type,
                    'title': report.title,
                    'description': report.description,
                    'status': report.status,
                    'date_from': report.date_from.isoformat(),
                    'date_to': report.date_to.isoformat(),
                    'created_by': report.created_by.username,
                    'created_at': report.created_at.isoformat(),
                    'completed_at': report.completed_at.isoformat() if report.completed_at else None,
                    'record_count': report.record_count,
                    'file_size': report.file_size
                }
                reports_data.append(report_dict)
            
            return paginator.get_paginated_response({
                'success': True,
                'reports': reports_data
            })
            
        except Exception as e:
            return StandardErrorResponse.server_error(
                message="Failed to retrieve compliance reports",
                request_id=getattr(request, 'request_id', None)
            ).to_response()
    
    def post(self, request):
        """
        Generate new compliance report
        """
        try:
            # Validate required fields
            report_type = request.data.get('report_type')
            date_from_str = request.data.get('date_from')
            date_to_str = request.data.get('date_to')
            
            if not all([report_type, date_from_str, date_to_str]):
                return StandardErrorResponse.validation_error(
                    message="Missing required fields",
                    details={
                        'required_fields': ['report_type', 'date_from', 'date_to']
                    },
                    request_id=getattr(request, 'request_id', None)
                ).to_response()
            
            # Parse dates
            try:
                date_from = datetime.fromisoformat(date_from_str.replace('Z', '+00:00'))
                date_to = datetime.fromisoformat(date_to_str.replace('Z', '+00:00'))
            except ValueError:
                return StandardErrorResponse.validation_error(
                    message="Invalid date format",
                    details={'expected_format': 'ISO 8601 (YYYY-MM-DDTHH:MM:SSZ)'},
                    request_id=getattr(request, 'request_id', None)
                ).to_response()
            
            # Validate report type
            valid_types = [choice[0] for choice in ComplianceReport.REPORT_TYPES]
            if report_type not in valid_types:
                return StandardErrorResponse.validation_error(
                    message="Invalid report type",
                    details={'valid_types': valid_types},
                    request_id=getattr(request, 'request_id', None)
                ).to_response()
            
            # Get optional filters
            filters = request.data.get('filters', {})
            
            # Generate report
            report = audit_service.generate_compliance_report(
                report_type=report_type,
                date_from=date_from,
                date_to=date_to,
                filters=filters,
                created_by=request.user
            )
            
            return Response({
                'success': True,
                'message': 'Compliance report generation started',
                'report_id': str(report.id),
                'status': report.status
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return StandardErrorResponse.server_error(
                message="Failed to generate compliance report",
                request_id=getattr(request, 'request_id', None)
            ).to_response()


class SecurityMetricsView(APIView):
    """
    Security metrics and statistics
    """
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]
    
    def get(self, request):
        """
        Get security metrics and statistics
        """
        try:
            days = int(request.GET.get('days', 30))
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)
            
            # Security event metrics
            total_events = SecurityEvent.objects.filter(timestamp__gte=start_date).count()
            high_risk_events = SecurityEvent.objects.filter(
                timestamp__gte=start_date,
                risk_score__gte=70
            ).count()
            blocked_events = SecurityEvent.objects.filter(
                timestamp__gte=start_date,
                is_blocked=True
            ).count()
            
            # Authentication metrics
            auth_attempts = SecurityEvent.objects.filter(
                timestamp__gte=start_date,
                event_type__in=['authentication_success', 'authentication_failure']
            ).count()
            
            auth_failures = SecurityEvent.objects.filter(
                timestamp__gte=start_date,
                event_type='authentication_failure'
            ).count()
            
            success_rate = ((auth_attempts - auth_failures) / auth_attempts * 100) if auth_attempts > 0 else 0
            
            # Alert metrics
            active_alerts = SecurityAlert.objects.filter(status__in=['open', 'investigating']).count()
            resolved_alerts = SecurityAlert.objects.filter(
                resolved_at__gte=start_date
            ).count()
            
            # Top threat sources
            top_threat_ips = SecurityEvent.objects.filter(
                timestamp__gte=start_date,
                risk_score__gte=50
            ).values('ip_address').annotate(
                threat_score=Sum('risk_score'),
                event_count=Count('id')
            ).order_by('-threat_score')[:10]
            
            # Audit trail metrics
            audit_records = AuditTrail.objects.filter(timestamp__gte=start_date).count()
            sensitive_changes = AuditTrail.objects.filter(
                timestamp__gte=start_date,
                is_sensitive=True
            ).count()
            
            return Response({
                'success': True,
                'metrics': {
                    'period': {
                        'days': days,
                        'start_date': start_date.isoformat(),
                        'end_date': end_date.isoformat()
                    },
                    'security_events': {
                        'total': total_events,
                        'high_risk': high_risk_events,
                        'blocked': blocked_events
                    },
                    'authentication': {
                        'total_attempts': auth_attempts,
                        'failures': auth_failures,
                        'success_rate': round(success_rate, 2)
                    },
                    'alerts': {
                        'active': active_alerts,
                        'resolved': resolved_alerts
                    },
                    'audit_trail': {
                        'total_records': audit_records,
                        'sensitive_changes': sensitive_changes
                    },
                    'top_threat_sources': list(top_threat_ips)
                }
            })
            
        except Exception as e:
            return StandardErrorResponse.server_error(
                message="Failed to retrieve security metrics",
                request_id=getattr(request, 'request_id', None)
            ).to_response()


# Convenience API endpoints
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def log_user_action(request):
    """
    API endpoint to manually log user actions
    """
    try:
        action = request.data.get('action')
        details = request.data.get('details', {})
        
        if not action:
            return StandardErrorResponse.validation_error(
                message="Action is required",
                request_id=getattr(request, 'request_id', None)
            ).to_response()
        
        # Log the action
        audit_entry = audit_service.log_user_action(
            action=action,
            user=request.user,
            request=request,
            details=details
        )
        
        return Response({
            'success': True,
            'message': 'User action logged successfully',
            'audit_id': str(audit_entry.id)
        })
        
    except Exception as e:
        return StandardErrorResponse.server_error(
            message="Failed to log user action",
            request_id=getattr(request, 'request_id', None)
        ).to_response()


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, permissions.IsAdminUser])
def security_summary(request):
    """
    Get security summary for quick overview
    """
    try:
        # Get counts for last 24 hours
        last_24h = timezone.now() - timedelta(hours=24)
        
        summary = {
            'last_24_hours': {
                'security_events': SecurityEvent.objects.filter(timestamp__gte=last_24h).count(),
                'high_risk_events': SecurityEvent.objects.filter(
                    timestamp__gte=last_24h,
                    risk_score__gte=70
                ).count(),
                'authentication_failures': SecurityEvent.objects.filter(
                    timestamp__gte=last_24h,
                    event_type='authentication_failure'
                ).count(),
                'blocked_activities': SecurityEvent.objects.filter(
                    timestamp__gte=last_24h,
                    is_blocked=True
                ).count()
            },
            'active_alerts': SecurityAlert.objects.filter(
                status__in=['open', 'investigating']
            ).count(),
            'system_status': 'operational'  # This could be enhanced with health checks
        }
        
        return Response({
            'success': True,
            'summary': summary
        })
        
    except Exception as e:
        return StandardErrorResponse.server_error(
            message="Failed to retrieve security summary",
            request_id=getattr(request, 'request_id', None)
        ).to_response()