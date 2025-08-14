"""
Security Event Service
Comprehensive security event logging, monitoring, and analysis
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from django.db import models as django_models
from django.core.cache import cache
from django.conf import settings
from .models import SecurityEvent, SecurityAlert, AuditTrail
from .error_response import SecureLogger

User = get_user_model()
logger = SecureLogger(__name__)


class SecurityEventService:
    """
    Service for managing security events and threat detection
    """
    
    # Risk scoring weights
    RISK_WEIGHTS = {
        'authentication_failure': 10,
        'brute_force_detected': 50,
        'sql_injection_attempt': 80,
        'xss_attempt': 60,
        'malware_detected': 90,
        'suspicious_activity': 30,
        'rate_limit_exceeded': 20,
        'file_upload_blocked': 40,
        'intrusion_detected': 100,
    }
    
    # Alert thresholds
    ALERT_THRESHOLDS = {
        'failed_logins_per_ip': 5,  # Failed logins from same IP
        'failed_logins_per_user': 3,  # Failed logins for same user
        'suspicious_events_per_ip': 10,  # Suspicious events from same IP
        'high_risk_events': 3,  # High risk events in timeframe
        'time_window_minutes': 15,  # Time window for threshold checks
    }
    
    def __init__(self):
        self.logger = SecureLogger('security_events')
    
    def log_authentication_attempt(self, username: str, success: bool, ip_address: str, 
                                 user_agent: str, request=None, additional_data: Dict = None) -> SecurityEvent:
        """
        Log authentication attempts with risk assessment
        """
        user = None
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        
        event_type = 'authentication_success' if success else 'authentication_failure'
        severity = 'low' if success else 'medium'
        
        event_data = {
            'username': username,
            'success': success,
            'user_exists': user is not None,
            **(additional_data or {})
        }
        
        # Calculate risk score
        risk_score = self._calculate_authentication_risk(username, ip_address, success, user_agent)
        
        # Log the event
        event = SecurityEvent.log_event(
            event_type=event_type,
            ip_address=ip_address,
            user=user,
            severity=severity,
            message=f"Authentication {'successful' if success else 'failed'} for {username}",
            event_data=event_data,
            request=request,
            risk_score=risk_score
        )
        
        # Check for alerts if authentication failed
        if not success:
            self._check_authentication_alerts(username, ip_address, user)
        
        # Log to secure logger
        self.logger.log_authentication_attempt(username, success, ip_address, user_agent)
        
        return event
    
    def log_suspicious_activity(self, activity_type: str, ip_address: str, 
                              user=None, request=None, details: Dict = None) -> SecurityEvent:
        """
        Log suspicious activities with automatic threat assessment
        """
        severity = self._determine_activity_severity(activity_type)
        risk_score = self.RISK_WEIGHTS.get(activity_type, 30)
        
        event_data = {
            'activity_type': activity_type,
            'details': details or {},
            'automated_detection': True
        }
        
        message = f"Suspicious activity detected: {activity_type}"
        if details:
            message += f" - {details.get('description', '')}"
        
        event = SecurityEvent.log_event(
            event_type='suspicious_activity',
            ip_address=ip_address,
            user=user,
            severity=severity,
            message=message,
            event_data=event_data,
            request=request,
            risk_score=risk_score
        )
        
        # Check for alerts
        self._check_suspicious_activity_alerts(ip_address, activity_type, user)
        
        # Log to secure logger
        self.logger.log_suspicious_activity(activity_type, 
                                          user_id=user.id if user else None,
                                          ip_address=ip_address, 
                                          details=details)
        
        return event
    
    def log_file_upload_event(self, filename: str, file_size: int, content_type: str,
                            is_blocked: bool, threat_level: str, ip_address: str,
                            user=None, request=None, scan_results: Dict = None) -> SecurityEvent:
        """
        Log file upload events with security analysis
        """
        event_type = 'file_upload_blocked' if is_blocked else 'file_upload'
        severity = self._map_threat_level_to_severity(threat_level)
        
        event_data = {
            'filename': filename,
            'file_size': file_size,
            'content_type': content_type,
            'is_blocked': is_blocked,
            'threat_level': threat_level,
            'scan_results': scan_results or {}
        }
        
        risk_score = self._calculate_file_upload_risk(threat_level, is_blocked, scan_results)
        
        message = f"File upload {'blocked' if is_blocked else 'allowed'}: {filename} ({threat_level} threat)"
        
        event = SecurityEvent.log_event(
            event_type=event_type,
            ip_address=ip_address,
            user=user,
            severity=severity,
            message=message,
            event_data=event_data,
            request=request,
            risk_score=risk_score,
        )
        
        # Create alert for blocked uploads with high threat level
        if is_blocked and threat_level in ['HIGH', 'CRITICAL']:
            self._create_file_upload_alert(event, user, ip_address)
        
        return event
    
    def log_permission_denied(self, user, resource: str, action: str, ip_address: str,
                            request=None, reason: str = '') -> SecurityEvent:
        """
        Log permission denied events
        """
        event_data = {
            'resource': resource,
            'action': action,
            'reason': reason,
            'user_roles': list(user.groups.values_list('name', flat=True)) if user else []
        }
        
        # Higher risk if accessing sensitive resources
        risk_score = self._calculate_permission_risk(resource, action, user)
        severity = 'high' if risk_score > 50 else 'medium'
        
        event = SecurityEvent.log_event(
            event_type='authorization_failure',
            ip_address=ip_address,
            user=user,
            severity=severity,
            message=f"Permission denied: {action} on {resource}",
            event_data=event_data,
            request=request,
            risk_score=risk_score
        )
        
        # Check for privilege escalation attempts
        self._check_privilege_escalation_alerts(user, resource, ip_address)
        
        return event
    
    def log_data_access(self, user, data_type: str, record_count: int, ip_address: str,
                       request=None, is_sensitive: bool = False) -> SecurityEvent:
        """
        Log sensitive data access events
        """
        event_data = {
            'data_type': data_type,
            'record_count': record_count,
            'is_sensitive': is_sensitive,
            'access_method': request.method if request else 'unknown'
        }
        
        severity = 'high' if is_sensitive else 'low'
        risk_score = 20 if is_sensitive else 5
        
        event = SecurityEvent.log_event(
            event_type='data_access',
            ip_address=ip_address,
            user=user,
            severity=severity,
            message=f"Data access: {data_type} ({record_count} records)",
            event_data=event_data,
            request=request,
            risk_score=risk_score
        )
        
        return event
    
    def get_security_dashboard_data(self, days: int = 7) -> Dict[str, Any]:
        """
        Get security dashboard data for monitoring
        """
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Get event counts by type
        event_counts = SecurityEvent.objects.filter(
            timestamp__gte=start_date
        ).values('event_type').annotate(count=Count('id')).order_by('-count')
        
        # Get severity distribution
        severity_counts = SecurityEvent.objects.filter(
            timestamp__gte=start_date
        ).values('severity').annotate(count=Count('id'))
        
        # Get top risk IPs
        top_risk_ips = SecurityEvent.objects.filter(
            timestamp__gte=start_date
        ).values('ip_address').annotate(
            total_risk=django_models.Sum('risk_score'),
            event_count=Count('id')
        ).order_by('-total_risk')[:10]
        
        # Get recent high-risk events
        high_risk_events = SecurityEvent.objects.filter(
            timestamp__gte=start_date,
            risk_score__gte=50
        ).order_by('-timestamp')[:20]
        
        # Get active alerts
        active_alerts = SecurityAlert.objects.filter(
            status__in=['open', 'investigating']
        ).order_by('-created_at')[:10]
        
        # Get authentication failure trends
        auth_failures = SecurityEvent.objects.filter(
            timestamp__gte=start_date,
            event_type='authentication_failure'
        ).extra(
            select={'date': 'DATE(timestamp)'}
        ).values('date').annotate(count=Count('id')).order_by('date')
        
        return {
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': days
            },
            'event_counts': list(event_counts),
            'severity_distribution': list(severity_counts),
            'top_risk_ips': list(top_risk_ips),
            'high_risk_events': [event.to_dict() for event in high_risk_events],
            'active_alerts': [alert.__dict__ for alert in active_alerts],
            'authentication_failure_trend': list(auth_failures),
            'total_events': SecurityEvent.objects.filter(timestamp__gte=start_date).count(),
            'blocked_events': SecurityEvent.objects.filter(
                timestamp__gte=start_date, 
                is_blocked=True
            ).count()
        }
    
    def _calculate_authentication_risk(self, username: str, ip_address: str, 
                                     success: bool, user_agent: str) -> int:
        """
        Calculate risk score for authentication attempts
        """
        risk_score = 0
        
        if not success:
            risk_score += 10
            
            # Check recent failures from same IP
            recent_failures = SecurityEvent.objects.filter(
                ip_address=ip_address,
                event_type='authentication_failure',
                timestamp__gte=timezone.now() - timedelta(minutes=15)
            ).count()
            
            risk_score += min(recent_failures * 10, 50)
            
            # Check recent failures for same username
            user_failures = SecurityEvent.objects.filter(
                event_data__username=username,
                event_type='authentication_failure',
                timestamp__gte=timezone.now() - timedelta(minutes=15)
            ).count()
            
            risk_score += min(user_failures * 15, 60)
        
        # Check for suspicious user agents
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'burp', 'owasp']
        if any(agent in user_agent.lower() for agent in suspicious_agents):
            risk_score += 30
        
        return min(risk_score, 100)
    
    def _determine_activity_severity(self, activity_type: str) -> str:
        """
        Determine severity level based on activity type
        """
        high_severity = ['sql_injection_attempt', 'xss_attempt', 'malware_detected', 'intrusion_detected']
        medium_severity = ['suspicious_activity', 'file_upload_blocked', 'brute_force_detected']
        
        if activity_type in high_severity:
            return 'high'
        elif activity_type in medium_severity:
            return 'medium'
        else:
            return 'low'
    
    def _map_threat_level_to_severity(self, threat_level: str) -> str:
        """
        Map threat level to severity
        """
        mapping = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return mapping.get(threat_level, 'medium')
    
    def _calculate_file_upload_risk(self, threat_level: str, is_blocked: bool, 
                                  scan_results: Dict = None) -> int:
        """
        Calculate risk score for file uploads
        """
        base_scores = {
            'CRITICAL': 90,
            'HIGH': 70,
            'MEDIUM': 40,
            'LOW': 10
        }
        
        risk_score = base_scores.get(threat_level, 20)
        
        if is_blocked:
            risk_score += 20
        
        if scan_results:
            if scan_results.get('malware_detected'):
                risk_score += 30
            if scan_results.get('suspicious_patterns'):
                risk_score += 15
        
        return min(risk_score, 100)
    
    def _calculate_permission_risk(self, resource: str, action: str, user) -> int:
        """
        Calculate risk score for permission denied events
        """
        risk_score = 20  # Base score
        
        # Higher risk for sensitive resources
        sensitive_resources = ['/admin/', '/api/admin/', '/financial/', '/users/', '/reports/']
        if any(sensitive in resource for sensitive in sensitive_resources):
            risk_score += 30
        
        # Higher risk for destructive actions
        destructive_actions = ['DELETE', 'POST', 'PUT', 'PATCH']
        if action in destructive_actions:
            risk_score += 20
        
        return min(risk_score, 100)
    
    def _check_authentication_alerts(self, username: str, ip_address: str, user):
        """
        Check if authentication failures warrant an alert
        """
        time_window = timezone.now() - timedelta(minutes=self.ALERT_THRESHOLDS['time_window_minutes'])
        
        # Check failed logins from same IP
        ip_failures = SecurityEvent.objects.filter(
            ip_address=ip_address,
            event_type='authentication_failure',
            timestamp__gte=time_window
        ).count()
        
        if ip_failures >= self.ALERT_THRESHOLDS['failed_logins_per_ip']:
            self._create_brute_force_alert(ip_address, ip_failures)
        
        # Check failed logins for same user
        if user:
            user_failures = SecurityEvent.objects.filter(
                user=user,
                event_type='authentication_failure',
                timestamp__gte=time_window
            ).count()
            
            if user_failures >= self.ALERT_THRESHOLDS['failed_logins_per_user']:
                self._create_account_compromise_alert(user, user_failures)
    
    def _check_suspicious_activity_alerts(self, ip_address: str, activity_type: str, user):
        """
        Check if suspicious activities warrant an alert
        """
        time_window = timezone.now() - timedelta(minutes=self.ALERT_THRESHOLDS['time_window_minutes'])
        
        # Check suspicious events from same IP
        suspicious_count = SecurityEvent.objects.filter(
            ip_address=ip_address,
            event_type='suspicious_activity',
            timestamp__gte=time_window
        ).count()
        
        if suspicious_count >= self.ALERT_THRESHOLDS['suspicious_events_per_ip']:
            self._create_suspicious_activity_alert(ip_address, activity_type, suspicious_count)
    
    def _check_privilege_escalation_alerts(self, user, resource: str, ip_address: str):
        """
        Check for privilege escalation attempts
        """
        time_window = timezone.now() - timedelta(minutes=30)
        
        # Check multiple permission denials for sensitive resources
        sensitive_denials = SecurityEvent.objects.filter(
            user=user,
            event_type='authorization_failure',
            timestamp__gte=time_window,
            event_data__resource__icontains='admin'
        ).count()
        
        if sensitive_denials >= 3:
            self._create_privilege_escalation_alert(user, resource, sensitive_denials)
    
    def _create_brute_force_alert(self, ip_address: str, failure_count: int):
        """
        Create brute force attack alert
        """
        alert, created = SecurityAlert.objects.get_or_create(
            alert_type='brute_force',
            status='open',
            defaults={
                'severity': 'high',
                'title': f'Brute Force Attack from {ip_address}',
                'description': f'Detected {failure_count} failed login attempts from IP {ip_address}',
                'first_seen': timezone.now(),
                'last_seen': timezone.now(),
                'event_count': failure_count,
                'risk_score': min(failure_count * 10, 100),
                'affected_ips': [ip_address]
            }
        )
        
        if not created:
            alert.last_seen = timezone.now()
            alert.event_count += 1
            alert.save()
    
    def _create_account_compromise_alert(self, user, failure_count: int):
        """
        Create account compromise alert
        """
        alert, created = SecurityAlert.objects.get_or_create(
            alert_type='account_compromise',
            status='open',
            defaults={
                'severity': 'high',
                'title': f'Potential Account Compromise: {user.username}',
                'description': f'Multiple failed login attempts for user {user.username}',
                'first_seen': timezone.now(),
                'last_seen': timezone.now(),
                'event_count': failure_count,
                'risk_score': min(failure_count * 15, 100)
            }
        )
        
        if not created:
            alert.last_seen = timezone.now()
            alert.event_count += 1
            alert.save()
        
        alert.affected_users.add(user)
    
    def _create_suspicious_activity_alert(self, ip_address: str, activity_type: str, event_count: int):
        """
        Create suspicious activity alert
        """
        alert, created = SecurityAlert.objects.get_or_create(
            alert_type='unusual_activity',
            status='open',
            defaults={
                'severity': 'medium',
                'title': f'Unusual Activity from {ip_address}',
                'description': f'Multiple suspicious activities detected: {activity_type}',
                'first_seen': timezone.now(),
                'last_seen': timezone.now(),
                'event_count': event_count,
                'risk_score': min(event_count * 5, 100),
                'affected_ips': [ip_address]
            }
        )
        
        if not created:
            alert.last_seen = timezone.now()
            alert.event_count += 1
            alert.save()
    
    def _create_privilege_escalation_alert(self, user, resource: str, denial_count: int):
        """
        Create privilege escalation alert
        """
        alert, created = SecurityAlert.objects.get_or_create(
            alert_type='privilege_escalation',
            status='open',
            defaults={
                'severity': 'high',
                'title': f'Privilege Escalation Attempt: {user.username}',
                'description': f'Multiple attempts to access restricted resource: {resource}',
                'first_seen': timezone.now(),
                'last_seen': timezone.now(),
                'event_count': denial_count,
                'risk_score': min(denial_count * 20, 100)
            }
        )
        
        if not created:
            alert.last_seen = timezone.now()
            alert.event_count += 1
            alert.save()
        
        alert.affected_users.add(user)
    
    def _create_file_upload_alert(self, event: SecurityEvent, user, ip_address: str):
        """
        Create file upload security alert
        """
        SecurityAlert.objects.create(
            alert_type='malware_detected',
            severity='critical',
            status='open',
            title='Malicious File Upload Blocked',
            description=f'Blocked malicious file upload from {ip_address}',
            first_seen=timezone.now(),
            last_seen=timezone.now(),
            event_count=1,
            risk_score=90,
            affected_ips=[ip_address]
        )


# Global instance
security_event_service = SecurityEventService()