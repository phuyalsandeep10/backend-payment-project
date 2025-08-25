"""
Error Monitoring Dashboard for PRS Backend
Provides web-based dashboard for error tracking and monitoring
"""

import json
import math
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Any, Optional

from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.contrib.admin.views.decorators import staff_member_required
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.db.models import Count, Q
from django.template.loader import render_to_string

from .error_correlation import error_tracker, ErrorCluster
from .structured_logger import StructuredLogger, EventType


class ErrorDashboardData:
    """Data aggregation for error monitoring dashboard"""
    
    def __init__(self):
        self.logger = StructuredLogger('error_dashboard')
    
    def get_dashboard_overview(self, hours: int = 24) -> Dict[str, Any]:
        """Get overview data for the dashboard"""
        summary = error_tracker.get_error_summary(hours)
        
        # Calculate metrics
        overview = {
            'total_error_clusters': summary['total_clusters'],
            'active_error_clusters': summary['active_clusters'], 
            'total_error_occurrences': summary['total_occurrences'],
            'new_error_patterns': len(summary['new_errors']),
            'critical_errors': len(summary['critical_errors']),
            'error_rate': self._calculate_error_rate(summary['total_occurrences'], hours),
            'severity_distribution': summary['severity_breakdown'],
            'health_score': self._calculate_health_score(summary),
            'time_period_hours': hours
        }
        
        return overview
    
    def get_error_trends(self, hours: int = 24) -> Dict[str, Any]:
        """Get error trends data for charts"""
        # Generate hourly buckets
        now = timezone.now()
        buckets = []
        error_counts = []
        
        for i in range(hours):
            bucket_start = now - timedelta(hours=hours-i)
            bucket_end = now - timedelta(hours=hours-i-1)
            buckets.append(bucket_start.strftime('%H:%M'))
            
            # Count errors in this hour
            count = self._count_errors_in_timerange(bucket_start, bucket_end)
            error_counts.append(count)
        
        return {
            'labels': buckets,
            'error_counts': error_counts,
            'trend_direction': self._calculate_trend(error_counts),
            'peak_hour': buckets[error_counts.index(max(error_counts))] if error_counts else None
        }
    
    def get_top_errors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top error patterns"""
        summary = error_tracker.get_error_summary(24)
        top_errors = summary['top_errors'][:limit]
        
        # Enhance with additional data
        enhanced_errors = []
        for error in top_errors:
            cluster = error_tracker.get_error_cluster(error['signature_hash'])
            if cluster:
                enhanced_error = error.copy()
                enhanced_error.update({
                    'error_pattern': cluster.signature.error_pattern,
                    'impact_score': self._calculate_impact_score(cluster),
                    'first_seen': cluster.first_occurrence,
                    'frequency': self._calculate_frequency(cluster),
                    'affected_ips': len(cluster.unique_ips),
                    'status': cluster.status
                })
                enhanced_errors.append(enhanced_error)
        
        return enhanced_errors
    
    def get_error_details(self, signature_hash: str) -> Dict[str, Any]:
        """Get detailed information about a specific error"""
        cluster = error_tracker.get_error_cluster(signature_hash)
        if not cluster:
            return None
        
        # Get related errors
        related_errors = error_tracker.get_related_errors(signature_hash)
        
        # Calculate statistics
        recent_occurrences = [occ for occ in cluster.occurrences 
                            if datetime.fromisoformat(occ.timestamp.replace('Z', '+00:00')) 
                            > datetime.now(timezone.utc) - timedelta(hours=24)]
        
        return {
            'cluster': cluster.to_dict(),
            'statistics': {
                'total_occurrences': cluster.occurrence_count,
                'recent_occurrences_24h': len(recent_occurrences),
                'unique_users_affected': len(cluster.unique_users),
                'unique_ips_affected': len(cluster.unique_ips),
                'first_occurrence': cluster.first_occurrence,
                'last_occurrence': cluster.last_occurrence,
                'duration_days': self._calculate_duration_days(cluster.first_occurrence, cluster.last_occurrence),
                'average_per_day': cluster.occurrence_count / max(1, self._calculate_duration_days(cluster.first_occurrence, cluster.last_occurrence)),
                'impact_score': self._calculate_impact_score(cluster),
                'severity_level': cluster.severity_level
            },
            'related_errors': [self._serialize_cluster(rel) for rel in related_errors],
            'occurrence_timeline': self._generate_occurrence_timeline(cluster),
            'affected_endpoints': self._get_affected_endpoints(cluster),
            'user_impact_analysis': self._analyze_user_impact(cluster)
        }
    
    def get_system_health_metrics(self) -> Dict[str, Any]:
        """Get overall system health metrics"""
        # Get error patterns
        summary_24h = error_tracker.get_error_summary(24)
        summary_7d = error_tracker.get_error_summary(24 * 7)
        
        # Calculate health indicators
        health_metrics = {
            'error_rate_24h': self._calculate_error_rate(summary_24h['total_occurrences'], 24),
            'error_rate_7d': self._calculate_error_rate(summary_7d['total_occurrences'], 24 * 7),
            'new_error_patterns_24h': len(summary_24h['new_errors']),
            'critical_errors_24h': len(summary_24h['critical_errors']),
            'resolved_errors_24h': self._count_resolved_errors(24),
            'system_stability_score': self._calculate_stability_score(summary_24h, summary_7d),
            'alert_status': self._get_alert_status(summary_24h),
            'top_error_categories': self._categorize_errors(summary_24h['top_errors']),
            'performance_impact': self._assess_performance_impact(summary_24h)
        }
        
        return health_metrics
    
    def get_user_impact_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get user impact analysis"""
        summary = error_tracker.get_error_summary(hours)
        
        # Aggregate user impact data
        total_affected_users = set()
        user_error_counts = defaultdict(int)
        organization_impact = defaultdict(int)
        
        for cluster in error_tracker.error_clusters.values():
            for user_id in cluster.unique_users:
                if user_id:
                    total_affected_users.add(user_id)
                    user_error_counts[user_id] += cluster.occurrence_count
            
            # Count organization impact
            for occurrence in cluster.occurrences[-10:]:  # Recent occurrences
                if occurrence.organization_id:
                    organization_impact[occurrence.organization_id] += 1
        
        return {
            'total_affected_users': len(total_affected_users),
            'users_with_multiple_errors': len([uid for uid, count in user_error_counts.items() if count > 1]),
            'most_affected_users': sorted(user_error_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'organization_impact': dict(organization_impact),
            'error_distribution': self._analyze_error_distribution(total_affected_users, user_error_counts),
            'recovery_patterns': self._analyze_recovery_patterns(hours)
        }
    
    def _calculate_error_rate(self, total_errors: int, hours: int) -> float:
        """Calculate error rate per hour"""
        return round(total_errors / max(1, hours), 2)
    
    def _calculate_health_score(self, summary: Dict[str, Any]) -> int:
        """Calculate system health score (0-100)"""
        score = 100
        
        # Penalty for active errors
        if summary['active_clusters'] > 0:
            score -= min(50, summary['active_clusters'] * 2)
        
        # Penalty for critical errors
        critical_count = summary['severity_breakdown'].get('critical', 0)
        if critical_count > 0:
            score -= min(30, critical_count * 10)
        
        # Penalty for high error rates
        error_rate = summary['total_occurrences'] / 24  # per hour
        if error_rate > 10:
            score -= min(20, (error_rate - 10))
        
        return max(0, int(score))
    
    def _count_errors_in_timerange(self, start_time: datetime, end_time: datetime) -> int:
        """Count errors in specific time range"""
        count = 0
        for cluster in error_tracker.error_clusters.values():
            for occurrence in cluster.occurrences:
                occ_time = datetime.fromisoformat(occurrence.timestamp.replace('Z', '+00:00'))
                if start_time <= occ_time < end_time:
                    count += 1
        return count
    
    def _calculate_trend(self, values: List[int]) -> str:
        """Calculate trend direction"""
        if len(values) < 2:
            return 'stable'
        
        recent_avg = sum(values[-3:]) / 3 if len(values) >= 3 else values[-1]
        older_avg = sum(values[:3]) / 3 if len(values) >= 3 else values[0]
        
        if recent_avg > older_avg * 1.2:
            return 'increasing'
        elif recent_avg < older_avg * 0.8:
            return 'decreasing' 
        else:
            return 'stable'
    
    def _calculate_impact_score(self, cluster: ErrorCluster) -> int:
        """Calculate impact score for an error cluster"""
        score = 0
        
        # Occurrence count impact
        score += min(50, cluster.occurrence_count)
        
        # User impact
        score += min(30, len(cluster.unique_users) * 2)
        
        # Severity multiplier
        severity_multipliers = {'low': 1, 'medium': 1.5, 'high': 2, 'critical': 3}
        score *= severity_multipliers.get(cluster.severity_level, 1)
        
        # IP diversity (indicates widespread issue)
        score += min(20, len(cluster.unique_ips))
        
        return int(score)
    
    def _calculate_frequency(self, cluster: ErrorCluster) -> str:
        """Calculate error frequency description"""
        duration_hours = self._calculate_duration_hours(cluster.first_occurrence, cluster.last_occurrence)
        
        if duration_hours == 0:
            return "Just occurred"
        
        rate = cluster.occurrence_count / duration_hours
        
        if rate >= 10:
            return "Very frequent (>10/hour)"
        elif rate >= 1:
            return f"Frequent ({rate:.1f}/hour)"
        elif rate >= 0.1:
            return f"Occasional ({rate:.2f}/hour)"
        else:
            return "Rare"
    
    def _calculate_duration_days(self, start: str, end: str) -> int:
        """Calculate duration in days between timestamps"""
        start_dt = datetime.fromisoformat(start.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end.replace('Z', '+00:00'))
        return max(1, (end_dt - start_dt).days)
    
    def _calculate_duration_hours(self, start: str, end: str) -> float:
        """Calculate duration in hours between timestamps"""
        start_dt = datetime.fromisoformat(start.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end.replace('Z', '+00:00'))
        return max(0.1, (end_dt - start_dt).total_seconds() / 3600)
    
    def _serialize_cluster(self, cluster: ErrorCluster) -> Dict[str, Any]:
        """Serialize cluster for JSON response"""
        return {
            'signature_hash': cluster.signature.signature_hash,
            'error_type': cluster.signature.error_type,
            'error_location': cluster.signature.error_location,
            'error_pattern': cluster.signature.error_pattern,
            'occurrence_count': cluster.occurrence_count,
            'severity_level': cluster.severity_level,
            'impact_score': self._calculate_impact_score(cluster)
        }
    
    def _generate_occurrence_timeline(self, cluster: ErrorCluster) -> List[Dict[str, Any]]:
        """Generate timeline of error occurrences"""
        timeline = []
        
        # Group occurrences by hour
        hourly_counts = defaultdict(int)
        for occurrence in cluster.occurrences:
            hour = datetime.fromisoformat(occurrence.timestamp.replace('Z', '+00:00')).replace(minute=0, second=0, microsecond=0)
            hourly_counts[hour] += 1
        
        # Convert to timeline format
        for hour, count in sorted(hourly_counts.items()):
            timeline.append({
                'timestamp': hour.isoformat(),
                'count': count
            })
        
        return timeline[-24:]  # Last 24 hours
    
    def _get_affected_endpoints(self, cluster: ErrorCluster) -> List[Dict[str, Any]]:
        """Get endpoints affected by this error"""
        endpoint_counts = defaultdict(int)
        
        for occurrence in cluster.occurrences:
            endpoint = f"{occurrence.request_method} {occurrence.request_path}"
            endpoint_counts[endpoint] += 1
        
        return [
            {'endpoint': endpoint, 'count': count}
            for endpoint, count in sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
        ][:10]
    
    def _analyze_user_impact(self, cluster: ErrorCluster) -> Dict[str, Any]:
        """Analyze user impact for a specific cluster"""
        user_occurrences = defaultdict(int)
        user_details = {}
        
        for occurrence in cluster.occurrences:
            if occurrence.user_id:
                user_occurrences[occurrence.user_id] += 1
                user_details[occurrence.user_id] = {
                    'organization_id': occurrence.organization_id,
                    'last_error': occurrence.timestamp
                }
        
        return {
            'total_users_affected': len(user_occurrences),
            'most_affected_users': sorted(user_occurrences.items(), key=lambda x: x[1], reverse=True)[:5],
            'user_distribution': dict(user_occurrences),
            'repeat_users': len([uid for uid, count in user_occurrences.items() if count > 1])
        }
    
    def _count_resolved_errors(self, hours: int) -> int:
        """Count resolved errors in the time period"""
        return len([cluster for cluster in error_tracker.error_clusters.values() 
                   if cluster.status == 'resolved'])
    
    def _calculate_stability_score(self, summary_24h: Dict, summary_7d: Dict) -> int:
        """Calculate system stability score"""
        score = 100
        
        # Compare 24h vs 7d trends
        rate_24h = summary_24h['total_occurrences'] / 24
        rate_7d = summary_7d['total_occurrences'] / (24 * 7)
        
        if rate_24h > rate_7d * 2:  # Significant increase
            score -= 20
        
        # New error patterns indicate instability
        score -= min(30, len(summary_24h['new_errors']) * 5)
        
        # Critical errors severely impact stability
        score -= min(40, len(summary_24h['critical_errors']) * 10)
        
        return max(0, score)
    
    def _get_alert_status(self, summary: Dict) -> str:
        """Get current alert status"""
        if len(summary['critical_errors']) > 0:
            return 'critical'
        elif summary['total_occurrences'] > 100:
            return 'warning'
        elif len(summary['new_errors']) > 5:
            return 'attention'
        else:
            return 'normal'
    
    def _categorize_errors(self, top_errors: List[Dict]) -> Dict[str, int]:
        """Categorize errors by type"""
        categories = defaultdict(int)
        
        for error in top_errors:
            error_type = error.get('error_type', 'Unknown')
            
            if 'Database' in error_type or 'database' in error.get('error_location', '').lower():
                categories['Database'] += error.get('occurrence_count', 0)
            elif 'Auth' in error_type or 'auth' in error.get('error_location', '').lower():
                categories['Authentication'] += error.get('occurrence_count', 0)
            elif 'Validation' in error_type:
                categories['Validation'] += error.get('occurrence_count', 0)
            elif 'Permission' in error_type:
                categories['Permission'] += error.get('occurrence_count', 0)
            else:
                categories['System'] += error.get('occurrence_count', 0)
        
        return dict(categories)
    
    def _assess_performance_impact(self, summary: Dict) -> str:
        """Assess performance impact of errors"""
        total_errors = summary['total_occurrences']
        
        if total_errors > 500:
            return 'severe'
        elif total_errors > 100:
            return 'moderate'
        elif total_errors > 20:
            return 'minor'
        else:
            return 'minimal'
    
    def _analyze_error_distribution(self, affected_users: set, user_error_counts: Dict) -> Dict[str, Any]:
        """Analyze error distribution patterns"""
        if not user_error_counts:
            return {'pattern': 'no_errors'}
        
        error_counts = list(user_error_counts.values())
        avg_errors = sum(error_counts) / len(error_counts)
        max_errors = max(error_counts)
        
        if max_errors > avg_errors * 3:
            return {'pattern': 'concentrated', 'description': 'Few users experiencing many errors'}
        elif len([c for c in error_counts if c > 1]) > len(error_counts) * 0.5:
            return {'pattern': 'widespread', 'description': 'Many users experiencing multiple errors'}
        else:
            return {'pattern': 'distributed', 'description': 'Errors distributed across users'}
    
    def _analyze_recovery_patterns(self, hours: int) -> Dict[str, Any]:
        """Analyze error recovery patterns"""
        # This would analyze how quickly errors are resolved
        # and users recover from error states
        resolved_clusters = [cluster for cluster in error_tracker.error_clusters.values() 
                           if cluster.status == 'resolved']
        
        if not resolved_clusters:
            return {'pattern': 'insufficient_data'}
        
        avg_resolution_time = sum(
            self._calculate_duration_hours(cluster.first_occurrence, cluster.last_occurrence)
            for cluster in resolved_clusters
        ) / len(resolved_clusters)
        
        if avg_resolution_time < 1:
            return {'pattern': 'fast_recovery', 'avg_hours': avg_resolution_time}
        elif avg_resolution_time < 24:
            return {'pattern': 'normal_recovery', 'avg_hours': avg_resolution_time}
        else:
            return {'pattern': 'slow_recovery', 'avg_hours': avg_resolution_time}


@method_decorator(staff_member_required, name='dispatch')
class ErrorDashboardView(View):
    """Main error monitoring dashboard view"""
    
    def get(self, request):
        dashboard_data = ErrorDashboardData()
        
        # Get time period from query params
        hours = int(request.GET.get('hours', 24))
        
        context = {
            'overview': dashboard_data.get_dashboard_overview(hours),
            'trends': dashboard_data.get_error_trends(hours),
            'top_errors': dashboard_data.get_top_errors(10),
            'health_metrics': dashboard_data.get_system_health_metrics(),
            'user_impact': dashboard_data.get_user_impact_report(hours),
            'hours': hours
        }
        
        return render(request, 'error_monitoring/dashboard.html', context)


@method_decorator(staff_member_required, name='dispatch')
class ErrorDashboardAPIView(View):
    """API endpoint for dashboard data"""
    
    def get(self, request):
        dashboard_data = ErrorDashboardData()
        hours = int(request.GET.get('hours', 24))
        
        data = {
            'overview': dashboard_data.get_dashboard_overview(hours),
            'trends': dashboard_data.get_error_trends(hours),
            'top_errors': dashboard_data.get_top_errors(10),
            'health_metrics': dashboard_data.get_system_health_metrics(),
            'user_impact': dashboard_data.get_user_impact_report(hours)
        }
        
        return JsonResponse(data)


@method_decorator(staff_member_required, name='dispatch')
class ErrorDetailView(View):
    """Detailed view for specific error"""
    
    def get(self, request, signature_hash):
        dashboard_data = ErrorDashboardData()
        error_details = dashboard_data.get_error_details(signature_hash)
        
        if not error_details:
            return JsonResponse({'error': 'Error not found'}, status=404)
        
        if request.GET.get('format') == 'json':
            return JsonResponse(error_details)
        
        return render(request, 'error_monitoring/error_detail.html', {
            'error_details': error_details,
            'signature_hash': signature_hash
        })


@method_decorator(staff_member_required, name='dispatch')
class ErrorActionView(View):
    """Handle error management actions"""
    
    def post(self, request, signature_hash):
        action = request.POST.get('action')
        
        if action == 'resolve':
            error_tracker.mark_cluster_resolved(
                signature_hash, 
                resolved_by=request.user.email
            )
            return JsonResponse({'success': True, 'message': 'Error marked as resolved'})
        
        elif action == 'investigate':
            # Mark as under investigation
            cluster = error_tracker.get_error_cluster(signature_hash)
            if cluster:
                cluster.status = 'investigating'
                return JsonResponse({'success': True, 'message': 'Error marked as under investigation'})
        
        return JsonResponse({'error': 'Invalid action'}, status=400)


# URL patterns for the dashboard
def get_error_monitoring_urls():
    """Get URL patterns for error monitoring dashboard"""
    from django.urls import path
    
    return [
        path('error-dashboard/', ErrorDashboardView.as_view(), name='error_dashboard'),
        path('error-dashboard/api/', ErrorDashboardAPIView.as_view(), name='error_dashboard_api'),
        path('error-dashboard/error/<str:signature_hash>/', ErrorDetailView.as_view(), name='error_detail'),
        path('error-dashboard/action/<str:signature_hash>/', ErrorActionView.as_view(), name='error_action'),
    ]
