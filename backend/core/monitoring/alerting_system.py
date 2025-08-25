"""
Alerting System
Comprehensive alerting system for performance and system monitoring
"""

from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache
from datetime import timedelta, datetime
from typing import Dict, List, Optional, Any
import logging
import json
import threading
import time
from collections import defaultdict, deque

from .performance_monitor import performance_monitor

logger = logging.getLogger('alerting')

class AlertingSystem:
    """
    Comprehensive alerting system for performance monitoring
    """
    
    # Singleton instance
    _instance = None
    _lock = threading.Lock()
    
    # Alert configuration
    ALERT_COOLDOWN_MINUTES = 15  # Minimum time between same alerts
    MAX_ALERTS_PER_HOUR = 10  # Maximum alerts per hour per type
    EMAIL_BATCH_SIZE = 5  # Maximum emails to send in one batch
    
    # Alert severity levels
    SEVERITY_INFO = 'info'
    SEVERITY_WARNING = 'warning'
    SEVERITY_CRITICAL = 'critical'
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize alerting system"""
        self.alert_history = deque(maxlen=10000)  # Last 10k alerts
        self.alert_cooldowns = {}  # Track cooldown periods
        self.alert_counts = defaultdict(int)  # Track alert frequency
        self.notification_channels = []  # List of notification channels
        self.alert_rules = []  # List of alert rules
        
        # Default alert rules
        self._setup_default_alert_rules()
        
        # Start background alert processing
        self._start_alert_processor()
    
    def _setup_default_alert_rules(self):
        """Setup default alert rules"""
        self.alert_rules = [
            {
                'name': 'high_cpu_usage',
                'condition': lambda metrics: metrics.get('cpu_percent', 0) > 80,
                'severity': self.SEVERITY_WARNING,
                'message_template': 'High CPU usage detected: {cpu_percent:.1f}%',
                'cooldown_minutes': 15
            },
            {
                'name': 'high_memory_usage',
                'condition': lambda metrics: metrics.get('memory_percent', 0) > 80,
                'severity': self.SEVERITY_WARNING,
                'message_template': 'High memory usage detected: {memory_percent:.1f}%',
                'cooldown_minutes': 15
            },
            {
                'name': 'low_disk_space',
                'condition': lambda metrics: metrics.get('disk_percent', 0) > 90,
                'severity': self.SEVERITY_CRITICAL,
                'message_template': 'Low disk space: {disk_percent:.1f}% used',
                'cooldown_minutes': 30
            },
            {
                'name': 'high_slow_query_rate',
                'condition': lambda metrics: self._calculate_slow_query_rate() > 20,
                'severity': self.SEVERITY_WARNING,
                'message_template': 'High slow query rate: {slow_query_rate:.1f}%',
                'cooldown_minutes': 10
            },
            {
                'name': 'high_api_error_rate',
                'condition': lambda metrics: self._calculate_api_error_rate() > 10,
                'severity': self.SEVERITY_WARNING,
                'message_template': 'High API error rate: {api_error_rate:.1f}%',
                'cooldown_minutes': 10
            },
            {
                'name': 'database_connection_issues',
                'condition': lambda metrics: metrics.get('db_connections', 0) > 50,
                'severity': self.SEVERITY_CRITICAL,
                'message_template': 'High database connection count: {db_connections}',
                'cooldown_minutes': 5
            }
        ]
    
    def _calculate_slow_query_rate(self) -> float:
        """Calculate current slow query rate"""
        if performance_monitor.total_queries == 0:
            return 0.0
        return (performance_monitor.slow_queries / performance_monitor.total_queries) * 100
    
    def _calculate_api_error_rate(self) -> float:
        """Calculate current API error rate"""
        if performance_monitor.total_api_calls == 0:
            return 0.0
        
        # Count recent errors (last hour)
        cutoff_time = timezone.now() - timedelta(hours=1)
        cutoff_str = cutoff_time.isoformat()
        
        recent_api_calls = [
            call for call in performance_monitor.api_metrics
            if call['timestamp'] >= cutoff_str
        ]
        
        if not recent_api_calls:
            return 0.0
        
        error_calls = [call for call in recent_api_calls if call['status_code'] >= 400]
        return (len(error_calls) / len(recent_api_calls)) * 100
    
    def _start_alert_processor(self):
        """Start background alert processing thread"""
        def process_alerts():
            while True:
                try:
                    self._check_alert_conditions()
                    self._cleanup_old_alerts()
                    time.sleep(60)  # Check every minute
                except Exception as e:
                    logger.error(f"Alert processing error: {str(e)}")
                    time.sleep(60)
        
        alert_thread = threading.Thread(target=process_alerts, daemon=True)
        alert_thread.start()
    
    def _check_alert_conditions(self):
        """Check all alert conditions and trigger alerts if needed"""
        try:
            # Get latest system metrics
            latest_metrics = list(performance_monitor.system_metrics)[-1] if performance_monitor.system_metrics else {}
            
            if not latest_metrics:
                return
            
            # Check each alert rule
            for rule in self.alert_rules:
                try:
                    if rule['condition'](latest_metrics):
                        self._trigger_alert(rule, latest_metrics)
                except Exception as e:
                    logger.error(f"Error checking alert rule '{rule['name']}': {str(e)}")
        
        except Exception as e:
            logger.error(f"Error checking alert conditions: {str(e)}")
    
    def _trigger_alert(self, rule: Dict, metrics: Dict):
        """Trigger an alert based on rule and metrics"""
        alert_name = rule['name']
        
        # Check cooldown period
        if self._is_in_cooldown(alert_name, rule.get('cooldown_minutes', 15)):
            return
        
        # Check alert frequency limits
        if self._exceeds_frequency_limit(alert_name):
            return
        
        # Create alert
        alert = {
            'id': f"{alert_name}_{int(time.time())}",
            'name': alert_name,
            'severity': rule['severity'],
            'message': rule['message_template'].format(**metrics, 
                                                      slow_query_rate=self._calculate_slow_query_rate(),
                                                      api_error_rate=self._calculate_api_error_rate()),
            'timestamp': timezone.now().isoformat(),
            'metrics': metrics.copy(),
            'rule': rule['name']
        }
        
        # Store alert
        self.alert_history.append(alert)
        
        # Update cooldown and frequency tracking
        self._update_cooldown(alert_name)
        self._update_frequency_count(alert_name)
        
        # Send notifications
        self._send_alert_notifications(alert)
        
        logger.warning(f"Alert triggered: {alert['message']}")
    
    def _is_in_cooldown(self, alert_name: str, cooldown_minutes: int) -> bool:
        """Check if alert is in cooldown period"""
        if alert_name not in self.alert_cooldowns:
            return False
        
        last_alert_time = self.alert_cooldowns[alert_name]
        cooldown_period = timedelta(minutes=cooldown_minutes)
        
        return timezone.now() - last_alert_time < cooldown_period
    
    def _exceeds_frequency_limit(self, alert_name: str) -> bool:
        """Check if alert exceeds frequency limits"""
        current_hour = timezone.now().replace(minute=0, second=0, microsecond=0)
        frequency_key = f"{alert_name}_{current_hour.isoformat()}"
        
        return self.alert_counts[frequency_key] >= self.MAX_ALERTS_PER_HOUR
    
    def _update_cooldown(self, alert_name: str):
        """Update cooldown timestamp for alert"""
        self.alert_cooldowns[alert_name] = timezone.now()
    
    def _update_frequency_count(self, alert_name: str):
        """Update frequency count for alert"""
        current_hour = timezone.now().replace(minute=0, second=0, microsecond=0)
        frequency_key = f"{alert_name}_{current_hour.isoformat()}"
        self.alert_counts[frequency_key] += 1
    
    def _send_alert_notifications(self, alert: Dict):
        """Send alert notifications through configured channels"""
        try:
            # Email notifications
            if self._should_send_email_alert(alert):
                self._send_email_alert(alert)
            
            # Log alert
            self._log_alert(alert)
            
            # Could add more notification channels here (Slack, SMS, etc.)
            
        except Exception as e:
            logger.error(f"Error sending alert notifications: {str(e)}")
    
    def _should_send_email_alert(self, alert: Dict) -> bool:
        """Determine if email alert should be sent"""
        # Only send email for warning and critical alerts
        if alert['severity'] not in [self.SEVERITY_WARNING, self.SEVERITY_CRITICAL]:
            return False
        
        # Check if email notifications are configured
        if not getattr(settings, 'EMAIL_HOST', None):
            return False
        
        # Check if admin emails are configured
        admin_emails = getattr(settings, 'ADMINS', [])
        if not admin_emails:
            return False
        
        return True
    
    def _send_email_alert(self, alert: Dict):
        """Send email alert to administrators"""
        try:
            admin_emails = [email for name, email in getattr(settings, 'ADMINS', [])]
            
            if not admin_emails:
                return
            
            subject = f"[PRS Alert] {alert['severity'].upper()}: {alert['name']}"
            
            message = f"""
Alert Details:
- Name: {alert['name']}
- Severity: {alert['severity']}
- Message: {alert['message']}
- Timestamp: {alert['timestamp']}

System Metrics:
{self._format_metrics_for_email(alert['metrics'])}

This is an automated alert from the PRS monitoring system.
"""
            
            send_mail(
                subject=subject,
                message=message,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@prs.com'),
                recipient_list=admin_emails,
                fail_silently=True
            )
            
            logger.info(f"Email alert sent for: {alert['name']}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")
    
    def _format_metrics_for_email(self, metrics: Dict) -> str:
        """Format metrics for email display"""
        formatted_lines = []
        
        key_metrics = [
            ('cpu_percent', 'CPU Usage', '%'),
            ('memory_percent', 'Memory Usage', '%'),
            ('disk_percent', 'Disk Usage', '%'),
            ('db_connections', 'DB Connections', ''),
            ('total_queries', 'Total Queries', ''),
            ('slow_queries', 'Slow Queries', '')
        ]
        
        for key, label, unit in key_metrics:
            if key in metrics:
                value = metrics[key]
                if isinstance(value, float):
                    formatted_lines.append(f"- {label}: {value:.1f}{unit}")
                else:
                    formatted_lines.append(f"- {label}: {value}{unit}")
        
        return '\n'.join(formatted_lines)
    
    def _log_alert(self, alert: Dict):
        """Log alert to application logs"""
        log_level = {
            self.SEVERITY_INFO: logger.info,
            self.SEVERITY_WARNING: logger.warning,
            self.SEVERITY_CRITICAL: logger.critical
        }.get(alert['severity'], logger.info)
        
        log_level(f"ALERT: {alert['message']} (Rule: {alert['rule']})")
    
    def _cleanup_old_alerts(self):
        """Clean up old alert tracking data"""
        try:
            # Clean up old frequency counts (older than 2 hours)
            cutoff_time = timezone.now() - timedelta(hours=2)
            
            keys_to_remove = []
            for key in self.alert_counts.keys():
                if '_' in key:
                    try:
                        timestamp_str = key.split('_', 1)[1]
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        if timestamp < cutoff_time:
                            keys_to_remove.append(key)
                    except (ValueError, IndexError):
                        keys_to_remove.append(key)  # Remove malformed keys
            
            for key in keys_to_remove:
                del self.alert_counts[key]
            
            # Clean up old cooldowns (older than 1 hour)
            cooldown_cutoff = timezone.now() - timedelta(hours=1)
            cooldowns_to_remove = [
                name for name, timestamp in self.alert_cooldowns.items()
                if timestamp < cooldown_cutoff
            ]
            
            for name in cooldowns_to_remove:
                del self.alert_cooldowns[name]
                
        except Exception as e:
            logger.error(f"Error cleaning up old alerts: {str(e)}")
    
    def add_alert_rule(self, rule: Dict):
        """Add a custom alert rule"""
        required_fields = ['name', 'condition', 'severity', 'message_template']
        
        if not all(field in rule for field in required_fields):
            raise ValueError(f"Alert rule must contain: {required_fields}")
        
        # Validate severity
        if rule['severity'] not in [self.SEVERITY_INFO, self.SEVERITY_WARNING, self.SEVERITY_CRITICAL]:
            raise ValueError(f"Invalid severity: {rule['severity']}")
        
        # Add default cooldown if not specified
        if 'cooldown_minutes' not in rule:
            rule['cooldown_minutes'] = 15
        
        self.alert_rules.append(rule)
        logger.info(f"Added alert rule: {rule['name']}")
    
    def remove_alert_rule(self, rule_name: str):
        """Remove an alert rule"""
        self.alert_rules = [rule for rule in self.alert_rules if rule['name'] != rule_name]
        logger.info(f"Removed alert rule: {rule_name}")
    
    def get_alert_history(self, hours: int = 24, severity: Optional[str] = None) -> List[Dict]:
        """Get alert history for specified period"""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        cutoff_str = cutoff_time.isoformat()
        
        alerts = [
            alert for alert in self.alert_history
            if alert['timestamp'] >= cutoff_str
        ]
        
        if severity:
            alerts = [alert for alert in alerts if alert['severity'] == severity]
        
        return sorted(alerts, key=lambda x: x['timestamp'], reverse=True)
    
    def get_alert_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get alert summary for specified period"""
        alerts = self.get_alert_history(hours=hours)
        
        # Group by severity
        by_severity = defaultdict(int)
        for alert in alerts:
            by_severity[alert['severity']] += 1
        
        # Group by rule
        by_rule = defaultdict(int)
        for alert in alerts:
            by_rule[alert['rule']] += 1
        
        # Recent alerts (last hour)
        recent_alerts = self.get_alert_history(hours=1)
        
        return {
            'period_hours': hours,
            'total_alerts': len(alerts),
            'by_severity': dict(by_severity),
            'by_rule': dict(by_rule),
            'recent_alerts': len(recent_alerts),
            'active_rules': len(self.alert_rules),
            'cooldowns_active': len(self.alert_cooldowns)
        }
    
    def test_alert_rule(self, rule_name: str) -> Dict[str, Any]:
        """Test an alert rule with current metrics"""
        rule = next((r for r in self.alert_rules if r['name'] == rule_name), None)
        
        if not rule:
            return {'error': f'Alert rule "{rule_name}" not found'}
        
        try:
            # Get latest metrics
            latest_metrics = list(performance_monitor.system_metrics)[-1] if performance_monitor.system_metrics else {}
            
            if not latest_metrics:
                return {'error': 'No system metrics available'}
            
            # Test condition
            condition_result = rule['condition'](latest_metrics)
            
            # Format message
            message = rule['message_template'].format(
                **latest_metrics,
                slow_query_rate=self._calculate_slow_query_rate(),
                api_error_rate=self._calculate_api_error_rate()
            )
            
            return {
                'rule_name': rule_name,
                'condition_met': condition_result,
                'message': message,
                'severity': rule['severity'],
                'metrics_used': latest_metrics,
                'in_cooldown': self._is_in_cooldown(rule_name, rule.get('cooldown_minutes', 15))
            }
            
        except Exception as e:
            return {'error': f'Error testing rule: {str(e)}'}

# Global alerting system instance
alerting_system = AlertingSystem()