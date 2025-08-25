"""
Alerting Views
API endpoints for managing the alerting system
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views import View
from django.utils import timezone
import json
import logging

from .alerting_system import alerting_system
from core_config.utils.decorators import require_organization_access, require_admin_access

logger = logging.getLogger(__name__)

class AlertingView(View):
    """Base view for alerting endpoints"""
    
    @method_decorator(login_required)
    @method_decorator(require_organization_access)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

@method_decorator(csrf_exempt, name='dispatch')
class AlertHistoryView(AlertingView):
    """Get alert history"""
    
    def get(self, request):
        try:
            hours = int(request.GET.get('hours', 24))
            hours = min(hours, 168)  # Limit to 1 week max
            
            severity = request.GET.get('severity')
            if severity and severity not in ['info', 'warning', 'critical']:
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid severity level'
                }, status=400)
            
            alerts = alerting_system.get_alert_history(hours=hours, severity=severity)
            
            return JsonResponse({
                'success': True,
                'data': {
                    'alerts': alerts,
                    'count': len(alerts),
                    'period_hours': hours,
                    'severity_filter': severity
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting alert history: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve alert history'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class AlertSummaryView(AlertingView):
    """Get alert summary"""
    
    def get(self, request):
        try:
            hours = int(request.GET.get('hours', 24))
            hours = min(hours, 168)  # Limit to 1 week max
            
            summary = alerting_system.get_alert_summary(hours=hours)
            
            return JsonResponse({
                'success': True,
                'data': summary
            })
            
        except Exception as e:
            logger.error(f"Error getting alert summary: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve alert summary'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(require_admin_access, name='dispatch')
class AlertRulesView(AlertingView):
    """Manage alert rules (admin only)"""
    
    def get(self, request):
        """Get all alert rules"""
        try:
            rules = []
            for rule in alerting_system.alert_rules:
                rule_info = {
                    'name': rule['name'],
                    'severity': rule['severity'],
                    'message_template': rule['message_template'],
                    'cooldown_minutes': rule.get('cooldown_minutes', 15)
                }
                rules.append(rule_info)
            
            return JsonResponse({
                'success': True,
                'data': {
                    'rules': rules,
                    'count': len(rules)
                }
            })
            
        except Exception as e:
            logger.error(f"Error getting alert rules: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve alert rules'
            }, status=500)
    
    def post(self, request):
        """Add a new alert rule"""
        try:
            data = json.loads(request.body)
            
            # Validate required fields
            required_fields = ['name', 'severity', 'message_template', 'condition_type']
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                return JsonResponse({
                    'success': False,
                    'error': f'Missing required fields: {missing_fields}'
                }, status=400)
            
            # Create condition function based on type
            condition_type = data['condition_type']
            condition_params = data.get('condition_params', {})
            
            if condition_type == 'cpu_threshold':
                threshold = float(condition_params.get('threshold', 80))
                condition = lambda metrics: metrics.get('cpu_percent', 0) > threshold
            
            elif condition_type == 'memory_threshold':
                threshold = float(condition_params.get('threshold', 80))
                condition = lambda metrics: metrics.get('memory_percent', 0) > threshold
            
            elif condition_type == 'disk_threshold':
                threshold = float(condition_params.get('threshold', 90))
                condition = lambda metrics: metrics.get('disk_percent', 0) > threshold
            
            elif condition_type == 'query_rate_threshold':
                threshold = float(condition_params.get('threshold', 20))
                condition = lambda metrics: alerting_system._calculate_slow_query_rate() > threshold
            
            elif condition_type == 'api_error_rate_threshold':
                threshold = float(condition_params.get('threshold', 10))
                condition = lambda metrics: alerting_system._calculate_api_error_rate() > threshold
            
            else:
                return JsonResponse({
                    'success': False,
                    'error': f'Unsupported condition type: {condition_type}'
                }, status=400)
            
            # Create rule
            rule = {
                'name': data['name'],
                'condition': condition,
                'severity': data['severity'],
                'message_template': data['message_template'],
                'cooldown_minutes': data.get('cooldown_minutes', 15)
            }
            
            # Add rule
            alerting_system.add_alert_rule(rule)
            
            logger.info(f"Alert rule '{data['name']}' added by user {request.user.id}")
            
            return JsonResponse({
                'success': True,
                'message': f"Alert rule '{data['name']}' added successfully"
            })
            
        except Exception as e:
            logger.error(f"Error adding alert rule: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to add alert rule'
            }, status=500)
    
    def delete(self, request):
        """Remove an alert rule"""
        try:
            data = json.loads(request.body)
            rule_name = data.get('name')
            
            if not rule_name:
                return JsonResponse({
                    'success': False,
                    'error': 'Rule name is required'
                }, status=400)
            
            # Check if rule exists
            rule_exists = any(rule['name'] == rule_name for rule in alerting_system.alert_rules)
            
            if not rule_exists:
                return JsonResponse({
                    'success': False,
                    'error': f'Alert rule "{rule_name}" not found'
                }, status=404)
            
            # Remove rule
            alerting_system.remove_alert_rule(rule_name)
            
            logger.info(f"Alert rule '{rule_name}' removed by user {request.user.id}")
            
            return JsonResponse({
                'success': True,
                'message': f"Alert rule '{rule_name}' removed successfully"
            })
            
        except Exception as e:
            logger.error(f"Error removing alert rule: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to remove alert rule'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(require_admin_access, name='dispatch')
class AlertRuleTestView(AlertingView):
    """Test alert rules (admin only)"""
    
    def post(self, request):
        """Test an alert rule"""
        try:
            data = json.loads(request.body)
            rule_name = data.get('rule_name')
            
            if not rule_name:
                return JsonResponse({
                    'success': False,
                    'error': 'Rule name is required'
                }, status=400)
            
            test_result = alerting_system.test_alert_rule(rule_name)
            
            if 'error' in test_result:
                return JsonResponse({
                    'success': False,
                    'error': test_result['error']
                }, status=400)
            
            return JsonResponse({
                'success': True,
                'data': test_result
            })
            
        except Exception as e:
            logger.error(f"Error testing alert rule: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to test alert rule'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class AlertStatusView(AlertingView):
    """Get current alert system status"""
    
    def get(self, request):
        try:
            # Get recent alerts (last hour)
            recent_alerts = alerting_system.get_alert_history(hours=1)
            
            # Count active cooldowns
            active_cooldowns = len(alerting_system.alert_cooldowns)
            
            # Get alert frequency for current hour
            current_hour = timezone.now().replace(minute=0, second=0, microsecond=0)
            current_hour_alerts = 0
            
            for key, count in alerting_system.alert_counts.items():
                if current_hour.isoformat() in key:
                    current_hour_alerts += count
            
            status = {
                'system_status': 'active',
                'total_rules': len(alerting_system.alert_rules),
                'recent_alerts': len(recent_alerts),
                'active_cooldowns': active_cooldowns,
                'current_hour_alerts': current_hour_alerts,
                'max_alerts_per_hour': alerting_system.MAX_ALERTS_PER_HOUR,
                'alert_cooldown_minutes': alerting_system.ALERT_COOLDOWN_MINUTES,
                'last_check': timezone.now().isoformat()
            }
            
            # Determine overall status
            if len(recent_alerts) > 5:
                status['system_status'] = 'high_activity'
            elif any(alert['severity'] == 'critical' for alert in recent_alerts):
                status['system_status'] = 'critical_alerts'
            
            return JsonResponse({
                'success': True,
                'data': status
            })
            
        except Exception as e:
            logger.error(f"Error getting alert status: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve alert status'
            }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(require_admin_access, name='dispatch')
class AlertConfigView(AlertingView):
    """Configure alerting system settings (admin only)"""
    
    def get(self, request):
        """Get current alerting configuration"""
        try:
            config = {
                'alert_cooldown_minutes': alerting_system.ALERT_COOLDOWN_MINUTES,
                'max_alerts_per_hour': alerting_system.MAX_ALERTS_PER_HOUR,
                'email_batch_size': alerting_system.EMAIL_BATCH_SIZE,
                'severity_levels': [
                    alerting_system.SEVERITY_INFO,
                    alerting_system.SEVERITY_WARNING,
                    alerting_system.SEVERITY_CRITICAL
                ]
            }
            
            return JsonResponse({
                'success': True,
                'data': config
            })
            
        except Exception as e:
            logger.error(f"Error getting alert config: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to retrieve alert configuration'
            }, status=500)
    
    def post(self, request):
        """Update alerting configuration"""
        try:
            data = json.loads(request.body)
            
            # Update configuration if provided
            if 'alert_cooldown_minutes' in data:
                alerting_system.ALERT_COOLDOWN_MINUTES = int(data['alert_cooldown_minutes'])
            
            if 'max_alerts_per_hour' in data:
                alerting_system.MAX_ALERTS_PER_HOUR = int(data['max_alerts_per_hour'])
            
            if 'email_batch_size' in data:
                alerting_system.EMAIL_BATCH_SIZE = int(data['email_batch_size'])
            
            logger.info(f"Alerting configuration updated by user {request.user.id}")
            
            return JsonResponse({
                'success': True,
                'message': 'Alerting configuration updated successfully'
            })
            
        except Exception as e:
            logger.error(f"Error updating alert config: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Failed to update alert configuration'
            }, status=500)

# Webhook endpoint for external monitoring systems
@require_http_methods(["POST"])
@csrf_exempt
def alert_webhook(request):
    """Webhook endpoint for receiving external alerts"""
    try:
        data = json.loads(request.body)
        
        # Validate webhook data
        required_fields = ['name', 'severity', 'message']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            return JsonResponse({
                'success': False,
                'error': f'Missing required fields: {missing_fields}'
            }, status=400)
        
        # Create external alert
        alert = {
            'id': f"external_{int(timezone.now().timestamp())}",
            'name': data['name'],
            'severity': data['severity'],
            'message': data['message'],
            'timestamp': timezone.now().isoformat(),
            'source': 'external',
            'metrics': data.get('metrics', {}),
            'rule': 'external_webhook'
        }
        
        # Validate severity
        valid_severities = [alerting_system.SEVERITY_INFO, alerting_system.SEVERITY_WARNING, alerting_system.SEVERITY_CRITICAL]
        if alert['severity'] not in valid_severities:
            return JsonResponse({
                'success': False,
                'error': f'Invalid severity. Must be one of: {valid_severities}'
            }, status=400)
        
        # Store alert
        alerting_system.alert_history.append(alert)
        
        # Send notifications for warning and critical alerts
        if alert['severity'] in [alerting_system.SEVERITY_WARNING, alerting_system.SEVERITY_CRITICAL]:
            alerting_system._send_alert_notifications(alert)
        
        logger.info(f"External alert received: {alert['name']}")
        
        return JsonResponse({
            'success': True,
            'message': 'Alert received and processed'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    
    except Exception as e:
        logger.error(f"Error processing webhook alert: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to process alert'
        }, status=500)