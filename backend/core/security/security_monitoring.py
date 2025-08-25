"""
Security Monitoring and Suspicious Activity Detection
Comprehensive security monitoring with real-time threat detection
"""

import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.http import HttpRequest
from django.db.models import Count, Q
from apps.authentication.models import SecurityEvent

# Security logger
security_logger = logging.getLogger('security')

User = get_user_model()

class SuspiciousActivityDetector:
    """
    Advanced suspicious activity detection system
    """
    
    # Thresholds for suspicious activity detection
    FAILED_LOGIN_THRESHOLD = 5  # Failed logins in time window
    RAPID_REQUEST_THRESHOLD = 50  # Requests per minute
    UNUSUAL_HOUR_THRESHOLD = 2  # Requests during unusual hours (2-6 AM)
    GEOGRAPHIC_ANOMALY_THRESHOLD = 2  # Different countries in short time
    USER_AGENT_CHANGE_THRESHOLD = 3  # Different user agents in short time
    
    # Time windows for analysis
    SHORT_WINDOW = timedelta(minutes=15)
    MEDIUM_WINDOW = timedelta(hours=1)
    LONG_WINDOW = timedelta(hours=24)
    
    def __init__(self):
        self.cache_prefix = 'security_monitor:'
    
    def analyze_request(self, request: HttpRequest, user=None) -> Dict[str, Any]:
        """
        Analyze incoming request for suspicious patterns
        
        Args:
            request: HTTP request object
            user: Authenticated user (if any)
            
        Returns:
            Dict with analysis results and risk indicators
        """
        ip_address = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        analysis = {
            'ip_address': ip_address,
            'user_agent_hash': hashlib.sha256(user_agent.encode()).hexdigest(),
            'risk_indicators': [],
            'risk_score': 0,
            'is_suspicious': False,
            'recommended_action': 'allow',
        }
        
        # Check various suspicious patterns
        self._check_rapid_requests(analysis, ip_address)
        self._check_failed_logins(analysis, ip_address, user)
        self._check_unusual_hours(analysis)
        self._check_user_agent_anomalies(analysis, ip_address, user_agent)
        self._check_geographic_anomalies(analysis, ip_address, user)
        self._check_known_threats(analysis, ip_address, user_agent)
        self._check_request_patterns(analysis, request)
        
        # Calculate overall risk score
        analysis['risk_score'] = min(sum(indicator.get('score', 0) for indicator in analysis['risk_indicators']), 100)
        
        # Determine if suspicious
        analysis['is_suspicious'] = analysis['risk_score'] >= 50
        
        # Recommend action based on risk score
        if analysis['risk_score'] >= 80:
            analysis['recommended_action'] = 'block'
        elif analysis['risk_score'] >= 60:
            analysis['recommended_action'] = 'challenge'
        elif analysis['risk_score'] >= 40:
            analysis['recommended_action'] = 'monitor'
        
        return analysis
    
    def _check_rapid_requests(self, analysis: Dict, ip_address: str):
        """Check for rapid request patterns"""
        cache_key = f"{self.cache_prefix}requests:{ip_address}"
        
        # Get current request count
        current_count = cache.get(cache_key, 0)
        cache.set(cache_key, current_count + 1, timeout=60)  # 1 minute window
        
        if current_count > self.RAPID_REQUEST_THRESHOLD:
            analysis['risk_indicators'].append({
                'type': 'rapid_requests',
                'description': f'Rapid requests detected: {current_count}/minute',
                'score': min(current_count - self.RAPID_REQUEST_THRESHOLD, 30),
                'severity': 'high' if current_count > self.RAPID_REQUEST_THRESHOLD * 2 else 'medium'
            })
    
    def _check_failed_logins(self, analysis: Dict, ip_address: str, user=None):
        """Check for failed login patterns"""
        # Check recent failed logins from this IP
        recent_failures = SecurityEvent.objects.filter(
            ip_address=ip_address,
            event_type='authentication_failure',
            timestamp__gte=timezone.now() - self.MEDIUM_WINDOW
        ).count()
        
        if recent_failures >= self.FAILED_LOGIN_THRESHOLD:
            analysis['risk_indicators'].append({
                'type': 'failed_logins',
                'description': f'Multiple failed logins: {recent_failures} attempts',
                'score': min(recent_failures * 5, 40),
                'severity': 'high' if recent_failures > self.FAILED_LOGIN_THRESHOLD * 2 else 'medium'
            })
        
        # Check for failed logins across multiple accounts from same IP
        if recent_failures > 0:
            unique_users = SecurityEvent.objects.filter(
                ip_address=ip_address,
                event_type='authentication_failure',
                timestamp__gte=timezone.now() - self.MEDIUM_WINDOW
            ).values('user_email').distinct().count()
            
            if unique_users > 3:
                analysis['risk_indicators'].append({
                    'type': 'credential_stuffing',
                    'description': f'Failed logins across {unique_users} different accounts',
                    'score': 35,
                    'severity': 'high'
                })
    
    def _check_unusual_hours(self, analysis: Dict):
        """Check for activity during unusual hours"""
        current_hour = timezone.now().hour
        
        # Consider 2 AM - 6 AM as unusual hours (adjust based on your user base)
        if 2 <= current_hour <= 6:
            # Check if this IP has recent activity during normal hours
            cache_key = f"{self.cache_prefix}normal_hours:{analysis['ip_address']}"
            normal_activity = cache.get(cache_key, False)
            
            if not normal_activity:
                analysis['risk_indicators'].append({
                    'type': 'unusual_hours',
                    'description': f'Activity during unusual hours: {current_hour}:00',
                    'score': 15,
                    'severity': 'medium'
                })
        else:
            # Mark normal hours activity
            cache_key = f"{self.cache_prefix}normal_hours:{analysis['ip_address']}"
            cache.set(cache_key, True, timeout=86400)  # 24 hours
    
    def _check_user_agent_anomalies(self, analysis: Dict, ip_address: str, user_agent: str):
        """Check for user agent switching patterns"""
        cache_key = f"{self.cache_prefix}user_agents:{ip_address}"
        
        # Get recent user agents for this IP
        user_agents = cache.get(cache_key, set())
        user_agent_hash = hashlib.sha256(user_agent.encode()).hexdigest()
        
        user_agents.add(user_agent_hash)
        cache.set(cache_key, user_agents, timeout=3600)  # 1 hour
        
        if len(user_agents) > self.USER_AGENT_CHANGE_THRESHOLD:
            analysis['risk_indicators'].append({
                'type': 'user_agent_switching',
                'description': f'Multiple user agents from same IP: {len(user_agents)}',
                'score': min(len(user_agents) * 5, 25),
                'severity': 'medium'
            })
    
    def _check_geographic_anomalies(self, analysis: Dict, ip_address: str, user=None):
        """Check for geographic anomalies (requires IP geolocation)"""
        # This would require an IP geolocation service
        # For now, we'll implement a basic version using stored data
        
        if user:
            # Check recent locations for this user
            recent_events = SecurityEvent.objects.filter(
                user=user,
                timestamp__gte=timezone.now() - self.LONG_WINDOW
            ).exclude(country__isnull=True).values('country').distinct()
            
            if recent_events.count() > 1:
                countries = [event['country'] for event in recent_events]
                analysis['risk_indicators'].append({
                    'type': 'geographic_anomaly',
                    'description': f'Access from multiple countries: {", ".join(countries)}',
                    'score': 20,
                    'severity': 'medium'
                })
    
    def _check_known_threats(self, analysis: Dict, ip_address: str, user_agent: str):
        """Check against known threat indicators"""
        # Check for known malicious IP patterns
        malicious_patterns = [
            'tor-exit',
            'proxy',
            'vpn',
            'bot',
            'crawler',
            'scanner'
        ]
        
        user_agent_lower = user_agent.lower()
        for pattern in malicious_patterns:
            if pattern in user_agent_lower:
                analysis['risk_indicators'].append({
                    'type': 'known_threat_pattern',
                    'description': f'Suspicious user agent pattern: {pattern}',
                    'score': 30,
                    'severity': 'high'
                })
                break
        
        # Check for suspicious IP ranges (this would be enhanced with threat intelligence)
        if ip_address.startswith(('10.', '192.168.', '172.')):
            # Private IP ranges might be suspicious in certain contexts
            pass
        
        # Check cache for known bad IPs
        cache_key = f"{self.cache_prefix}bad_ip:{ip_address}"
        if cache.get(cache_key):
            analysis['risk_indicators'].append({
                'type': 'known_bad_ip',
                'description': 'IP address flagged as malicious',
                'score': 50,
                'severity': 'critical'
            })
    
    def _check_request_patterns(self, analysis: Dict, request: HttpRequest):
        """Check for suspicious request patterns"""
        # Check for common attack patterns in URL
        suspicious_patterns = [
            'union select',
            'script>',
            '../',
            'cmd=',
            'exec(',
            'eval(',
            'base64_decode',
            'system(',
            'shell_exec',
            'passthru',
            'file_get_contents',
            'fopen',
            'fwrite',
            'include(',
            'require(',
        ]
        
        request_path = request.path.lower()
        query_string = request.META.get('QUERY_STRING', '').lower()
        full_url = f"{request_path}?{query_string}"
        
        for pattern in suspicious_patterns:
            if pattern in full_url:
                analysis['risk_indicators'].append({
                    'type': 'malicious_request_pattern',
                    'description': f'Suspicious pattern in request: {pattern}',
                    'score': 40,
                    'severity': 'high'
                })
                break
        
        # Check for unusual request methods
        if request.method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            analysis['risk_indicators'].append({
                'type': 'unusual_http_method',
                'description': f'Unusual HTTP method: {request.method}',
                'score': 15,
                'severity': 'medium'
            })
    
    def flag_ip_as_malicious(self, ip_address: str, reason: str, duration_hours: int = 24):
        """Flag an IP address as malicious"""
        cache_key = f"{self.cache_prefix}bad_ip:{ip_address}"
        cache.set(cache_key, {
            'reason': reason,
            'flagged_at': timezone.now().isoformat()
        }, timeout=duration_hours * 3600)
        
        security_logger.error(f"IP {ip_address} flagged as malicious: {reason}")
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip


class SecurityDashboard:
    """
    Security dashboard data provider
    """
    
    @staticmethod
    def get_dashboard_data(days: int = 7) -> Dict[str, Any]:
        """Get comprehensive security dashboard data"""
        return SecurityEvent.get_security_dashboard_data(days)
    
    @staticmethod
    def get_real_time_threats() -> List[Dict[str, Any]]:
        """Get real-time threat indicators"""
        # Get recent high-risk events
        recent_threats = SecurityEvent.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=1),
            risk_score__gte=70
        ).order_by('-timestamp')[:10]
        
        threats = []
        for event in recent_threats:
            threats.append({
                'id': event.id,
                'type': event.event_type,
                'severity': event.severity,
                'risk_score': event.risk_score,
                'ip_address': event.ip_address,
                'user_email': event.user_email,
                'description': event.event_description,
                'timestamp': event.timestamp,
                'is_investigated': event.is_investigated,
            })
        
        return threats
    
    @staticmethod
    def get_top_risk_ips(days: int = 7, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top risk IP addresses"""
        from django.db.models import Avg, Sum
        
        start_date = timezone.now() - timedelta(days=days)
        
        top_ips = SecurityEvent.objects.filter(
            timestamp__gte=start_date
        ).values('ip_address').annotate(
            event_count=Count('id'),
            avg_risk_score=Avg('risk_score'),
            total_risk_score=Sum('risk_score'),
            critical_events=Count('id', filter=Q(severity='critical')),
            high_events=Count('id', filter=Q(severity='high'))
        ).order_by('-total_risk_score')[:limit]
        
        return list(top_ips)
    
    @staticmethod
    def get_security_trends(days: int = 30) -> Dict[str, Any]:
        """Get security trends over time"""
        from django.db.models import Count
        from django.db.models.functions import TruncDate
        
        start_date = timezone.now() - timedelta(days=days)
        
        # Events by day
        daily_events = SecurityEvent.objects.filter(
            timestamp__gte=start_date
        ).annotate(
            date=TruncDate('timestamp')
        ).values('date').annotate(
            total_events=Count('id'),
            critical_events=Count('id', filter=Q(severity='critical')),
            high_events=Count('id', filter=Q(severity='high')),
            suspicious_events=Count('id', filter=Q(event_type='suspicious_activity'))
        ).order_by('date')
        
        return {
            'daily_events': list(daily_events),
            'total_days': days,
        }
    
    @staticmethod
    def get_investigation_queue() -> List[Dict[str, Any]]:
        """Get events requiring investigation"""
        uninvestigated = SecurityEvent.objects.filter(
            is_investigated=False,
            severity__in=['high', 'critical']
        ).order_by('-risk_score', '-timestamp')[:20]
        
        queue = []
        for event in uninvestigated:
            queue.append({
                'id': event.id,
                'event_type': event.event_type,
                'severity': event.severity,
                'risk_score': event.risk_score,
                'ip_address': event.ip_address,
                'user_email': event.user_email,
                'description': event.event_description,
                'timestamp': event.timestamp,
                'correlation_id': event.correlation_id,
            })
        
        return queue


class SecurityMiddleware:
    """
    Security monitoring middleware
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.detector = SuspiciousActivityDetector()
    
    def __call__(self, request):
        # Analyze request for suspicious patterns
        analysis = self.detector.analyze_request(request, getattr(request, 'user', None))
        
        # Store analysis in request for later use
        request.security_analysis = analysis
        
        # Log suspicious activity
        if analysis['is_suspicious']:
            from core_config.error_handling import security_event_logger
            
            security_event_logger.log_suspicious_activity(
                request=request,
                activity_type='automated_detection',
                details={
                    'risk_score': analysis['risk_score'],
                    'risk_indicators': analysis['risk_indicators'],
                    'recommended_action': analysis['recommended_action']
                }
            )
            
            # Block high-risk requests
            if analysis['recommended_action'] == 'block':
                from django.http import JsonResponse
                return JsonResponse({
                    'error': {
                        'code': 'SECURITY_BLOCK',
                        'message': 'Request blocked due to security policy'
                    }
                }, status=403)
        
        response = self.get_response(request)
        
        return response


# Global instances
suspicious_activity_detector = SuspiciousActivityDetector()
security_dashboard = SecurityDashboard()