"""
Performance Dashboard Views - Task 6.2.2

Advanced performance monitoring dashboard with real-time analytics,
alerting, and comprehensive reporting capabilities.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Any

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse, StreamingHttpResponse
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from apps.permissions.permissions import IsOrgAdminOrSuperAdmin

from .enhanced_performance_monitor import enhanced_performance_monitor
from .performance_monitor import performance_monitor

import logging

logger = logging.getLogger('performance_dashboard')


class PerformanceDashboardView(APIView):
    """
    Main performance dashboard providing comprehensive monitoring data
    Task 6.2.2: Performance alerting and reporting dashboard
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """Get comprehensive performance dashboard data"""
        try:
            hours = int(request.GET.get('hours', 24))
            include_trends = request.GET.get('trends', 'true').lower() == 'true'
            include_alerts = request.GET.get('alerts', 'true').lower() == 'true'
            
            # Get dashboard data from enhanced monitor
            dashboard_data = enhanced_performance_monitor.get_performance_dashboard_data(hours)
            
            # Add legacy monitor data for compatibility
            legacy_summary = performance_monitor.get_performance_summary(hours)
            
            # Combine data sources
            combined_data = {
                'enhanced_metrics': dashboard_data,
                'legacy_metrics': legacy_summary,
                'system_info': self._get_system_info(),
                'configuration': self._get_monitoring_configuration(),
                'health_status': self._get_system_health_status()
            }
            
            # Filter data based on request parameters
            if not include_trends:
                combined_data['enhanced_metrics'].pop('trends', None)
            
            if not include_alerts:
                combined_data['enhanced_metrics'].pop('active_alerts', None)
                combined_data['enhanced_metrics'].pop('alert_history', None)
            
            return Response(combined_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Dashboard data retrieval error: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve dashboard data', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for dashboard"""
        return {
            'monitoring_enabled': enhanced_performance_monitor.monitoring_enabled,
            'alert_enabled': enhanced_performance_monitor.alert_enabled,
            'trend_analysis_enabled': enhanced_performance_monitor.trend_analysis_enabled,
            'baseline_established': bool(enhanced_performance_monitor.baseline_metrics),
            'monitoring_interval': enhanced_performance_monitor.monitoring_interval,
            'data_retention_hours': enhanced_performance_monitor.METRICS_RETENTION_HOURS,
            'server_time': timezone.now().isoformat(),
            'version': getattr(settings, 'APP_VERSION', '1.0.0')
        }
    
    def _get_monitoring_configuration(self) -> Dict[str, Any]:
        """Get monitoring configuration"""
        return {
            'thresholds': {
                name: {
                    'metric_name': threshold.metric_name,
                    'warning_threshold': threshold.warning_threshold,
                    'critical_threshold': threshold.critical_threshold,
                    'enabled': threshold.enabled,
                    'consecutive_violations': threshold.consecutive_violations,
                    'cooldown_minutes': threshold.cooldown_minutes
                }
                for name, threshold in enhanced_performance_monitor.thresholds.items()
            },
            'regression_sensitivity': enhanced_performance_monitor.regression_sensitivity,
            'slow_query_threshold': enhanced_performance_monitor.SLOW_QUERY_THRESHOLD,
            'slow_api_threshold': enhanced_performance_monitor.SLOW_API_THRESHOLD
        }
    
    def _get_system_health_status(self) -> Dict[str, Any]:
        """Get overall system health status"""
        try:
            # Get current metrics
            current_metrics = cache.get('current_app_metrics', {})
            if not current_metrics:
                return {'status': 'unknown', 'message': 'No current metrics available'}
            
            # Check critical thresholds
            critical_issues = []
            warning_issues = []
            
            for name, threshold in enhanced_performance_monitor.thresholds.items():
                if not threshold.enabled:
                    continue
                
                metric_value = current_metrics.get(threshold.metric_name)
                if metric_value is None:
                    continue
                
                # Check critical threshold
                if threshold.comparison == 'greater' and metric_value > threshold.critical_threshold:
                    critical_issues.append(f"{threshold.metric_name}: {metric_value:.2f} > {threshold.critical_threshold}")
                elif threshold.comparison == 'less' and metric_value < threshold.critical_threshold:
                    critical_issues.append(f"{threshold.metric_name}: {metric_value:.2f} < {threshold.critical_threshold}")
                
                # Check warning threshold
                elif threshold.comparison == 'greater' and metric_value > threshold.warning_threshold:
                    warning_issues.append(f"{threshold.metric_name}: {metric_value:.2f} > {threshold.warning_threshold}")
                elif threshold.comparison == 'less' and metric_value < threshold.warning_threshold:
                    warning_issues.append(f"{threshold.metric_name}: {metric_value:.2f} < {threshold.warning_threshold}")
            
            # Determine overall status
            if critical_issues:
                status_level = 'critical'
                message = f"{len(critical_issues)} critical issues detected"
            elif warning_issues:
                status_level = 'warning'
                message = f"{len(warning_issues)} warning issues detected"
            else:
                status_level = 'healthy'
                message = 'All systems operating normally'
            
            return {
                'status': status_level,
                'message': message,
                'critical_issues': critical_issues,
                'warning_issues': warning_issues,
                'last_check': timezone.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Health status error: {e}")
            return {
                'status': 'error',
                'message': f'Health check failed: {str(e)}',
                'last_check': timezone.now().isoformat()
            }


class RealTimeMetricsView(APIView):
    """
    Real-time metrics streaming endpoint
    Task 6.2.2: Real-time performance monitoring
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """Stream real-time performance metrics"""
        def event_stream():
            """Generator for Server-Sent Events"""
            while True:
                try:
                    # Get current metrics
                    current_metrics = cache.get('current_app_metrics', {})
                    
                    if current_metrics:
                        # Format as Server-Sent Event
                        data = json.dumps(current_metrics)
                        yield f"data: {data}\n\n"
                    
                    # Wait for next update
                    import time
                    time.sleep(5)  # Update every 5 seconds
                    
                except Exception as e:
                    logger.error(f"Real-time streaming error: {e}")
                    yield f"data: {json.dumps({'error': str(e)})}\n\n"
        
        response = StreamingHttpResponse(
            event_stream(),
            content_type='text/event-stream'
        )
        response['Cache-Control'] = 'no-cache'
        response['Connection'] = 'keep-alive'
        
        return response


class PerformanceAlertsAPIView(APIView):
    """
    Performance alerts management API
    Task 6.2.2: Alert management and configuration
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """Get performance alerts"""
        try:
            # Query parameters
            hours = int(request.GET.get('hours', 24))
            severity = request.GET.get('severity')  # 'warning', 'critical'
            metric = request.GET.get('metric')
            active_only = request.GET.get('active_only', 'false').lower() == 'true'
            
            # Get alerts
            if active_only:
                alerts = list(enhanced_performance_monitor.active_alerts.values())
            else:
                # Get from history
                cutoff_time = timezone.now() - timedelta(hours=hours)
                alerts = [
                    alert for alert in enhanced_performance_monitor.alert_history
                    if alert.timestamp > cutoff_time
                ]
            
            # Apply filters
            if severity:
                alerts = [alert for alert in alerts if alert.severity == severity]
            
            if metric:
                alerts = [alert for alert in alerts if alert.metric_name == metric]
            
            # Serialize alerts
            alerts_data = [
                {
                    'alert_id': alert.alert_id,
                    'metric_name': alert.metric_name,
                    'severity': alert.severity,
                    'current_value': alert.current_value,
                    'threshold_value': alert.threshold_value,
                    'message': alert.message,
                    'timestamp': alert.timestamp.isoformat(),
                    'endpoint': alert.endpoint,
                    'organization_id': alert.organization_id,
                    'user_id': alert.user_id,
                    'metadata': alert.metadata
                }
                for alert in alerts
            ]
            
            return Response({
                'alerts': alerts_data,
                'count': len(alerts_data),
                'active_count': len(enhanced_performance_monitor.active_alerts),
                'total_history_count': len(enhanced_performance_monitor.alert_history)
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Alerts API error: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve alerts', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def post(self, request):
        """Acknowledge or dismiss alerts"""
        try:
            action = request.data.get('action')  # 'acknowledge', 'dismiss'
            alert_ids = request.data.get('alert_ids', [])
            
            if not action or not alert_ids:
                return Response(
                    {'error': 'Missing action or alert_ids'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            processed_alerts = []
            
            for alert_id in alert_ids:
                if alert_id in enhanced_performance_monitor.active_alerts:
                    alert = enhanced_performance_monitor.active_alerts[alert_id]
                    
                    if action == 'acknowledge':
                        alert.metadata['acknowledged'] = True
                        alert.metadata['acknowledged_by'] = request.user.id
                        alert.metadata['acknowledged_at'] = timezone.now().isoformat()
                    elif action == 'dismiss':
                        del enhanced_performance_monitor.active_alerts[alert_id]
                    
                    processed_alerts.append(alert_id)
            
            return Response({
                'action': action,
                'processed_alerts': processed_alerts,
                'message': f'Successfully {action}ed {len(processed_alerts)} alerts'
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Alert action error: {str(e)}")
            return Response(
                {'error': 'Failed to process alert action', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PerformanceThresholdsAPIView(APIView):
    """
    Performance thresholds configuration API
    Task 6.2.2: Threshold management
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """Get performance thresholds configuration"""
        try:
            thresholds_data = {}
            
            for name, threshold in enhanced_performance_monitor.thresholds.items():
                thresholds_data[name] = {
                    'metric_name': threshold.metric_name,
                    'warning_threshold': threshold.warning_threshold,
                    'critical_threshold': threshold.critical_threshold,
                    'comparison': threshold.comparison,
                    'consecutive_violations': threshold.consecutive_violations,
                    'cooldown_minutes': threshold.cooldown_minutes,
                    'enabled': threshold.enabled
                }
            
            return Response({
                'thresholds': thresholds_data,
                'available_metrics': list(thresholds_data.keys()),
                'regression_sensitivity': enhanced_performance_monitor.regression_sensitivity
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Thresholds API error: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve thresholds', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def put(self, request):
        """Update performance thresholds"""
        try:
            metric_name = request.data.get('metric_name')
            updates = request.data.get('updates', {})
            
            if not metric_name or not updates:
                return Response(
                    {'error': 'Missing metric_name or updates'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Update threshold
            enhanced_performance_monitor.update_threshold(metric_name, **updates)
            
            return Response({
                'message': f'Successfully updated threshold for {metric_name}',
                'metric_name': metric_name,
                'updates': updates
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Threshold update error: {str(e)}")
            return Response(
                {'error': 'Failed to update threshold', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PerformanceTrendsAPIView(APIView):
    """
    Performance trends analysis API
    Task 6.2.2: Trend analysis and reporting
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """Get performance trends analysis"""
        try:
            metric_name = request.GET.get('metric')
            hours = int(request.GET.get('hours', 24))
            
            if metric_name:
                # Get specific metric history
                history = enhanced_performance_monitor.get_metric_history(metric_name, hours)
                trend = enhanced_performance_monitor.performance_trends.get(metric_name)
                
                return Response({
                    'metric_name': metric_name,
                    'history': history,
                    'trend': {
                        'metric_name': trend.metric_name,
                        'timeframe': trend.timeframe,
                        'current_avg': trend.current_avg,
                        'previous_avg': trend.previous_avg,
                        'change_percent': trend.change_percent,
                        'trend_direction': trend.trend_direction,
                        'confidence': trend.confidence,
                        'data_points': trend.data_points
                    } if trend else None
                }, status=status.HTTP_200_OK)
            else:
                # Get all trends
                trends_data = {}
                for name, trend in enhanced_performance_monitor.performance_trends.items():
                    trends_data[name] = {
                        'metric_name': trend.metric_name,
                        'timeframe': trend.timeframe,
                        'current_avg': trend.current_avg,
                        'previous_avg': trend.previous_avg,
                        'change_percent': trend.change_percent,
                        'trend_direction': trend.trend_direction,
                        'confidence': trend.confidence,
                        'data_points': trend.data_points
                    }
                
                return Response({
                    'trends': trends_data,
                    'available_metrics': list(trends_data.keys()),
                    'timeframe_hours': hours
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            logger.error(f"Trends API error: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve trends', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PerformanceBaselineAPIView(APIView):
    """
    Performance baseline management API
    Task 6.2.2: Baseline establishment and management
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """Get current performance baseline"""
        try:
            baseline = enhanced_performance_monitor.baseline_metrics
            
            if not baseline:
                return Response({
                    'baseline_established': False,
                    'message': 'No performance baseline established'
                }, status=status.HTTP_200_OK)
            
            return Response({
                'baseline_established': True,
                'baseline_metrics': baseline,
                'metrics_count': len(baseline),
                'regression_sensitivity': enhanced_performance_monitor.regression_sensitivity
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Baseline API error: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve baseline', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def post(self, request):
        """Establish new performance baseline"""
        try:
            duration_minutes = int(request.data.get('duration_minutes', 60))
            
            # Establish baseline
            baseline = enhanced_performance_monitor.establish_performance_baseline(duration_minutes)
            
            return Response({
                'message': f'Performance baseline established with {duration_minutes} minutes of data',
                'baseline_metrics': baseline,
                'duration_minutes': duration_minutes,
                'established_at': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
            
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Baseline establishment error: {str(e)}")
            return Response(
                {'error': 'Failed to establish baseline', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PerformanceReportsAPIView(APIView):
    """
    Performance reports generation API
    Task 6.2.2: Comprehensive reporting
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def get(self, request):
        """Generate performance report"""
        try:
            report_type = request.GET.get('type', 'summary')  # 'summary', 'detailed', 'trends', 'alerts'
            hours = int(request.GET.get('hours', 24))
            format_type = request.GET.get('format', 'json')  # 'json', 'csv'
            
            if report_type == 'summary':
                report_data = self._generate_summary_report(hours)
            elif report_type == 'detailed':
                report_data = self._generate_detailed_report(hours)
            elif report_type == 'trends':
                report_data = self._generate_trends_report(hours)
            elif report_type == 'alerts':
                report_data = self._generate_alerts_report(hours)
            else:
                return Response(
                    {'error': 'Invalid report type'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if format_type == 'csv':
                # Convert to CSV format
                csv_response = self._convert_to_csv(report_data, report_type)
                return csv_response
            
            return Response(report_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Reports API error: {str(e)}")
            return Response(
                {'error': 'Failed to generate report', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _generate_summary_report(self, hours: int) -> Dict[str, Any]:
        """Generate summary performance report"""
        dashboard_data = enhanced_performance_monitor.get_performance_dashboard_data(hours)
        
        return {
            'report_type': 'summary',
            'timeframe_hours': hours,
            'generated_at': timezone.now().isoformat(),
            'system_health': dashboard_data.get('health_status', {}),
            'key_metrics': dashboard_data.get('averages', {}),
            'active_alerts_count': len(dashboard_data.get('active_alerts', [])),
            'trends_summary': {
                name: trend['trend_direction']
                for name, trend in dashboard_data.get('trends', {}).items()
            },
            'baseline_established': bool(dashboard_data.get('baseline_metrics', {}))
        }
    
    def _generate_detailed_report(self, hours: int) -> Dict[str, Any]:
        """Generate detailed performance report"""
        return enhanced_performance_monitor.get_performance_dashboard_data(hours)
    
    def _generate_trends_report(self, hours: int) -> Dict[str, Any]:
        """Generate trends analysis report"""
        trends = enhanced_performance_monitor.performance_trends
        
        return {
            'report_type': 'trends',
            'timeframe_hours': hours,
            'generated_at': timezone.now().isoformat(),
            'trends_analysis': {
                name: {
                    'metric_name': trend.metric_name,
                    'current_avg': trend.current_avg,
                    'previous_avg': trend.previous_avg,
                    'change_percent': trend.change_percent,
                    'trend_direction': trend.trend_direction,
                    'confidence': trend.confidence
                }
                for name, trend in trends.items()
            },
            'trends_count': len(trends),
            'improving_metrics': [
                name for name, trend in trends.items()
                if trend.trend_direction == 'improving'
            ],
            'degrading_metrics': [
                name for name, trend in trends.items()
                if trend.trend_direction == 'degrading'
            ]
        }
    
    def _generate_alerts_report(self, hours: int) -> Dict[str, Any]:
        """Generate alerts summary report"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        recent_alerts = [
            alert for alert in enhanced_performance_monitor.alert_history
            if alert.timestamp > cutoff_time
        ]
        
        # Group alerts by metric and severity
        alerts_by_metric = {}
        alerts_by_severity = {'warning': 0, 'critical': 0}
        
        for alert in recent_alerts:
            if alert.metric_name not in alerts_by_metric:
                alerts_by_metric[alert.metric_name] = []
            alerts_by_metric[alert.metric_name].append(alert)
            alerts_by_severity[alert.severity] += 1
        
        return {
            'report_type': 'alerts',
            'timeframe_hours': hours,
            'generated_at': timezone.now().isoformat(),
            'total_alerts': len(recent_alerts),
            'active_alerts': len(enhanced_performance_monitor.active_alerts),
            'alerts_by_severity': alerts_by_severity,
            'alerts_by_metric': {
                metric: len(alerts) for metric, alerts in alerts_by_metric.items()
            },
            'most_problematic_metrics': sorted(
                alerts_by_metric.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )[:5]
        }
    
    def _convert_to_csv(self, data: Dict[str, Any], report_type: str) -> StreamingHttpResponse:
        """Convert report data to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        
        if report_type == 'summary':
            writer = csv.writer(output)
            writer.writerow(['Metric', 'Value'])
            
            # Write key metrics
            for metric, values in data.get('key_metrics', {}).items():
                if isinstance(values, dict):
                    for key, value in values.items():
                        writer.writerow([f"{metric}_{key}", value])
                else:
                    writer.writerow([metric, values])
        
        response = StreamingHttpResponse(
            iter([output.getvalue()]),
            content_type='text/csv'
        )
        response['Content-Disposition'] = f'attachment; filename="performance_report_{report_type}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
