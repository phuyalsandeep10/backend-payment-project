"""
Emergency Response Templates

This module provides specialized emergency response templates for different
types of system failures, with particular focus on authentication failures.

Requirements addressed:
- 3.4: Emergency response templates for authentication failures
- 4.1: Standardized emergency response formats
"""

from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from django.utils import timezone
from rest_framework import status


class EmergencyTemplateManager:
    """
    Manages emergency response templates for different failure scenarios
    """
    
    def __init__(self):
        self.templates = self._initialize_templates()
        self.template_usage_count = {}
    
    def _initialize_templates(self) -> Dict[str, Dict[str, Any]]:
        """
        Initialize comprehensive emergency response templates
        """
        return {
            # Authentication-specific templates
            'auth_login_failure': {
                'error': {
                    'code': 'AUTH_LOGIN_EMERGENCY',
                    'message': 'Login service is temporarily unavailable due to system issues.',
                    'type': 'authentication_emergency',
                    'user_action': 'Please wait a few minutes and try logging in again.',
                    'retry_after': 300,
                    'alternative_access': 'If this is urgent, please contact your system administrator.',
                    'incident_id': None,  # Will be populated
                    'support_info': {
                        'contact_method': 'Please contact technical support if this issue persists',
                        'expected_resolution': '5-10 minutes',
                        'status_page': 'Check system status page for updates'
                    }
                },
                'status_code': status.HTTP_503_SERVICE_UNAVAILABLE
            },
            
            'auth_token_failure': {
                'error': {
                    'code': 'AUTH_TOKEN_EMERGENCY',
                    'message': 'Authentication token service is experiencing issues.',
                    'type': 'authentication_emergency',
                    'user_action': 'Please log out and log back in. If the problem persists, clear your browser cache.',
                    'retry_after': 180,
                    'technical_details': 'Token validation service temporarily unavailable',
                    'workaround': 'Try refreshing the page or logging out and back in'
                },
                'status_code': status.HTTP_503_SERVICE_UNAVAILABLE
            },
            
            'auth_permission_failure': {
                'error': {
                    'code': 'AUTH_PERMISSION_EMERGENCY',
                    'message': 'Permission verification system is temporarily unavailable.',
                    'type': 'authentication_emergency',
                    'user_action': 'Your permissions cannot be verified at this time. Please try again shortly.',
                    'retry_after': 240,
                    'impact': 'Some features may be temporarily inaccessible',
                    'escalation': 'Contact your administrator if you need immediate access'
                },
                'status_code': status.HTTP_503_SERVICE_UNAVAILABLE
            },
            
            'auth_session_failure': {
                'error': {
                    'code': 'AUTH_SESSION_EMERGENCY',
                    'message': 'Session management system is experiencing difficulties.',
                    'type': 'authentication_emergency',
                    'user_action': 'Please log out completely and log back in.',
                    'retry_after': 300,
                    'session_advice': 'Close all browser tabs and clear cookies if the problem continues',
                    'security_note': 'Your data remains secure during this temporary service interruption'
                },
                'status_code': status.HTTP_503_SERVICE_UNAVAILABLE
            },
            
            # Middleware-specific templates
            'middleware_rendering_failure': {
                'error': {
                    'code': 'MIDDLEWARE_RENDERING_EMERGENCY',
                    'message': 'Response rendering system is temporarily malfunctioning.',
                    'type': 'middleware_emergency',
                    'user_action': 'Please refresh the page. If the error persists, try again in a few minutes.',
                    'retry_after': 120,
                    'technical_info': 'Content rendering middleware failure detected',
                    'impact': 'Some pages may not display correctly'
                },
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR
            },
            
            'middleware_validation_failure': {
                'error': {
                    'code': 'MIDDLEWARE_VALIDATION_EMERGENCY',
                    'message': 'Request validation system is experiencing issues.',
                    'type': 'middleware_emergency',
                    'user_action': 'Please check your input and try again. Contact support if the problem continues.',
                    'retry_after': 180,
                    'validation_advice': 'Ensure all required fields are filled correctly',
                    'fallback': 'Basic validation is still active for security'
                },
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR
            },
            
            # Database-specific templates
            'database_connection_failure': {
                'error': {
                    'code': 'DATABASE_CONNECTION_EMERGENCY',
                    'message': 'Database connection is temporarily unavailable.',
                    'type': 'database_emergency',
                    'user_action': 'Please wait a moment and try your request again.',
                    'retry_after': 600,
                    'data_safety': 'Your data is safe. No information has been lost.',
                    'service_status': 'Database connectivity is being restored',
                    'estimated_recovery': '10-15 minutes'
                },
                'status_code': status.HTTP_503_SERVICE_UNAVAILABLE
            },
            
            'database_query_failure': {
                'error': {
                    'code': 'DATABASE_QUERY_EMERGENCY',
                    'message': 'Database query processing is experiencing delays.',
                    'type': 'database_emergency',
                    'user_action': 'Please try your request again. Complex operations may take longer than usual.',
                    'retry_after': 300,
                    'performance_note': 'System is operating in reduced performance mode',
                    'priority_info': 'Critical operations are being prioritized'
                },
                'status_code': status.HTTP_503_SERVICE_UNAVAILABLE
            },
            
            # Circuit breaker templates
            'circuit_breaker_auth_open': {
                'error': {
                    'code': 'CIRCUIT_BREAKER_AUTH_OPEN',
                    'message': 'Authentication system is in recovery mode due to repeated failures.',
                    'type': 'circuit_breaker_emergency',
                    'user_action': 'Please wait for the system to recover before attempting to log in again.',
                    'retry_after': 300,
                    'recovery_info': 'System is automatically testing recovery every few minutes',
                    'protection_note': 'This protection prevents further system damage',
                    'manual_override': 'Contact administrator for emergency access if critically needed'
                },
                'status_code': status.HTTP_503_SERVICE_UNAVAILABLE
            },
            
            'circuit_breaker_middleware_open': {
                'error': {
                    'code': 'CIRCUIT_BREAKER_MIDDLEWARE_OPEN',
                    'message': 'Request processing system is in recovery mode.',
                    'type': 'circuit_breaker_emergency',
                    'user_action': 'Please wait for automatic recovery before making new requests.',
                    'retry_after': 180,
                    'system_protection': 'This prevents cascading failures',
                    'recovery_status': 'System will automatically resume when stable'
                },
                'status_code': status.HTTP_503_SERVICE_UNAVAILABLE
            },
            
            # Critical system templates
            'critical_system_failure': {
                'error': {
                    'code': 'CRITICAL_SYSTEM_EMERGENCY',
                    'message': 'A critical system component has failed. Emergency protocols are active.',
                    'type': 'critical_emergency',
                    'user_action': 'Please stop current activities and try again later.',
                    'retry_after': 900,
                    'incident_status': 'Incident has been automatically reported to system administrators',
                    'data_protection': 'All data integrity protections remain active',
                    'escalation': 'Technical team has been automatically notified',
                    'emergency_contact': 'For urgent issues, contact emergency support line'
                },
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR
            },
            
            # Generic fallback template
            'generic_emergency': {
                'error': {
                    'code': 'GENERIC_EMERGENCY',
                    'message': 'An unexpected system issue has occurred. Emergency response is active.',
                    'type': 'generic_emergency',
                    'user_action': 'Please try your request again in a few minutes.',
                    'retry_after': 300,
                    'support_info': 'If this problem continues, please contact technical support',
                    'incident_tracking': 'This issue is being automatically tracked and resolved'
                },
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR
            }
        }
    
    def get_template(self, template_name: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Get an emergency response template with optional context customization
        """
        # Track template usage
        self.template_usage_count[template_name] = self.template_usage_count.get(template_name, 0) + 1
        
        # Get base template or fallback to generic
        template = self.templates.get(template_name, self.templates['generic_emergency']).copy()
        
        # Add standard metadata
        template['metadata'] = {
            'template_name': template_name,
            'generated_at': timezone.now().isoformat(),
            'template_version': '1.0',
            'usage_count': self.template_usage_count[template_name],
            'emergency_response_system': 'active'
        }
        
        # Add incident ID
        import uuid
        incident_id = str(uuid.uuid4())[:8]
        template['error']['incident_id'] = incident_id
        
        # Apply context customizations
        if context:
            template = self._apply_context(template, context)
        
        return template
    
    def _apply_context(self, template: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply context-specific customizations to template
        """
        # Add request-specific information
        if 'request_id' in context:
            template['metadata']['request_id'] = context['request_id']
        
        if 'endpoint' in context:
            template['metadata']['affected_endpoint'] = context['endpoint']
        
        if 'user_id' in context:
            template['metadata']['user_id'] = context['user_id']
        
        # Customize retry_after based on failure count
        if 'failure_count' in context:
            failure_count = context['failure_count']
            if failure_count > 5:
                # Increase retry time for repeated failures
                current_retry = template['error'].get('retry_after', 300)
                template['error']['retry_after'] = min(current_retry * 2, 1800)  # Max 30 minutes
                template['error']['repeated_failure_notice'] = f'Multiple failures detected ({failure_count}). Extended retry time applied.'
        
        # Add component-specific information
        if 'component' in context:
            component = context['component']
            template['error']['affected_component'] = component
            
            # Component-specific advice
            if component == 'authentication':
                template['error']['component_advice'] = 'Authentication services are being restored with high priority'
            elif component == 'database':
                template['error']['component_advice'] = 'Database connectivity is being restored'
            elif component == 'middleware':
                template['error']['component_advice'] = 'Request processing systems are being stabilized'
        
        # Add error details if provided (but sanitized)
        if 'error_details' in context:
            # Only include safe error details, not full stack traces
            error_details = str(context['error_details'])
            if len(error_details) > 200:
                error_details = error_details[:200] + '...'
            template['error']['technical_summary'] = error_details
        
        # Add timing information
        if 'estimated_recovery' in context:
            template['error']['estimated_recovery'] = context['estimated_recovery']
        
        return template
    
    def get_authentication_emergency_template(
        self, 
        failure_type: str = 'login', 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Get authentication-specific emergency template
        """
        template_map = {
            'login': 'auth_login_failure',
            'token': 'auth_token_failure',
            'permission': 'auth_permission_failure',
            'session': 'auth_session_failure'
        }
        
        template_name = template_map.get(failure_type, 'auth_login_failure')
        return self.get_template(template_name, context)
    
    def get_circuit_breaker_template(
        self, 
        component: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Get circuit breaker-specific emergency template
        """
        template_name = f'circuit_breaker_{component}_open'
        if template_name not in self.templates:
            template_name = 'circuit_breaker_auth_open'  # Default fallback
        
        return self.get_template(template_name, context)
    
    def get_usage_statistics(self) -> Dict[str, Any]:
        """
        Get template usage statistics
        """
        return {
            'total_templates': len(self.templates),
            'usage_count': self.template_usage_count.copy(),
            'most_used': max(self.template_usage_count.items(), key=lambda x: x[1]) if self.template_usage_count else None,
            'available_templates': list(self.templates.keys())
        }
    
    def create_custom_template(
        self, 
        name: str, 
        error_code: str, 
        message: str, 
        status_code: int = 500,
        additional_fields: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Create a custom emergency template
        """
        if name in self.templates:
            return False  # Template already exists
        
        template = {
            'error': {
                'code': error_code,
                'message': message,
                'type': 'custom_emergency',
                'user_action': 'Please try again later or contact support.',
                'retry_after': 300
            },
            'status_code': status_code
        }
        
        if additional_fields:
            template['error'].update(additional_fields)
        
        self.templates[name] = template
        return True


# Global template manager instance
template_manager = EmergencyTemplateManager()


def get_emergency_template(template_name: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to get emergency template
    """
    return template_manager.get_template(template_name, context)


def get_authentication_emergency(failure_type: str = 'login', context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to get authentication emergency template
    """
    return template_manager.get_authentication_emergency_template(failure_type, context)


def get_circuit_breaker_emergency(component: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to get circuit breaker emergency template
    """
    return template_manager.get_circuit_breaker_template(component, context)