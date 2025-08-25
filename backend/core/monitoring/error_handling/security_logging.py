"""
Security Logging

This module provides secure logging functionality including log sanitization
and comprehensive security event logging with database persistence.

Extracted from error_handling.py for better organization.
"""

import logging
import re
from typing import Dict, Any, Optional

# Security logger
security_logger = logging.getLogger('security')


class SecureLoggingFilter(logging.Filter):
    """
    Logging filter to sanitize log messages and prevent sensitive data leakage
    """
    
    # Sensitive patterns to remove from logs
    SENSITIVE_PATTERNS = [
        # Passwords and secrets
        (r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'password=***'),
        (r'secret["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'secret=***'),
        (r'token["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'token=***'),
        (r'key["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'key=***'),
        
        # API keys
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]+', 'api_key=***'),
        
        # Database URLs
        (r'postgresql://[^@]+@[^/]+/\w+', 'postgresql://***:***@***/***'),
        (r'mysql://[^@]+@[^/]+/\w+', 'mysql://***:***@***/***'),
        
        # Email addresses (in some contexts)
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***'),
        
        # Credit card numbers
        (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '****-****-****-****'),
        
        # Social security numbers
        (r'\b\d{3}-\d{2}-\d{4}\b', '***-**-****'),
        
        # Phone numbers (in some contexts)
        (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '***-***-****'),
    ]
    
    def filter(self, record):
        """Filter and sanitize log record"""
        if hasattr(record, 'msg') and record.msg:
            # Sanitize the log message
            sanitized_msg = str(record.msg)
            
            for pattern, replacement in self.SENSITIVE_PATTERNS:
                sanitized_msg = re.sub(pattern, replacement, sanitized_msg, flags=re.IGNORECASE)
            
            record.msg = sanitized_msg
        
        # Sanitize arguments
        if hasattr(record, 'args') and record.args:
            sanitized_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    sanitized_arg = arg
                    for pattern, replacement in self.SENSITIVE_PATTERNS:
                        sanitized_arg = re.sub(pattern, replacement, sanitized_arg, flags=re.IGNORECASE)
                    sanitized_args.append(sanitized_arg)
                else:
                    sanitized_args.append(arg)
            record.args = tuple(sanitized_args)
        
        return True


class SecurityEventLogger:
    """
    Enhanced security event logger with database persistence and structured logging
    """
    
    def __init__(self):
        self.logger = logging.getLogger('security')
    
    def log_security_event(self, request, event_type: str, event_data: Dict[str, Any] = None,
                          severity: str = 'medium', user=None, description: str = None) -> Optional[Any]:
        """
        Log a comprehensive security event to both database and logs
        
        Args:
            request: HTTP request object
            event_type: Type of security event
            event_data: Additional structured data
            severity: Event severity (low, medium, high, critical)
            user: User associated with the event
            description: Human-readable description
            
        Returns:
            SecurityEvent instance or None
        """
        # Import here to avoid circular imports
        try:
            from core_config.models import SecurityAlert as SecurityEvent
        except ImportError:
            try:
                from apps.authentication.models import SecurityEvent
            except ImportError:
                # Fallback to logging only if model not available
                self.logger.error(f"SecurityEvent model not available, logging only: {event_type}")
                return None
        
        # Extract request information
        ip_address = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Determine user from request if not provided
        if not user and hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user
        
        # Generate description if not provided
        if not description:
            description = self._generate_description(event_type, event_data)
        
        try:
            # Create security event
            security_event = SecurityEvent.objects.create(
                alert_type=event_type,
                severity=severity,
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                request_path=request.path,
                request_method=request.method,
                description=description,
                alert_data=event_data or {},
            )
            
            # Calculate and update risk score if method exists
            if hasattr(security_event, 'calculate_risk_score'):
                security_event.calculate_risk_score()
                security_event.save(update_fields=['risk_score'])
            
            # Log to traditional logging system as well
            log_level = self._get_log_level(severity)
            self.logger.log(log_level, description, extra={
                'event_id': security_event.id,
                'event_type': event_type,
                'severity': severity,
                'user_id': user.id if user else None,
                'ip_address': ip_address,
                'risk_score': getattr(security_event, 'risk_score', 0),
            })
            
            return security_event
            
        except Exception as e:
            # Fallback to logging only if database operation fails
            self.logger.error(f"Failed to create security event in database: {str(e)}")
            log_level = self._get_log_level(severity)
            self.logger.log(log_level, f"{description} (DB error: {str(e)})")
            return None
    
    def log_authentication_attempt(self, request, user_identifier: str, success: bool, 
                                 failure_reason: str = None, user=None):
        """Log authentication attempt with enhanced tracking"""
        event_type = 'authentication_success' if success else 'authentication_failure'
        severity = 'low' if success else 'medium'
        
        event_data = {
            'user_identifier': user_identifier,
            'success': success,
        }
        
        if not success and failure_reason:
            event_data['failure_reason'] = failure_reason
            # Increase severity for certain failure types
            if any(keyword in failure_reason.lower() for keyword in ['brute force', 'locked', 'suspicious']):
                severity = 'high'
        
        description = f"Authentication {'successful' if success else 'failed'} for {user_identifier}"
        if failure_reason:
            description += f": {failure_reason}"
        
        return self.log_security_event(
            request=request,
            event_type=event_type,
            event_data=event_data,
            severity=severity,
            user=user,
            description=description
        )
    
    def log_permission_denied(self, request, user, resource: str, action: str):
        """Log permission denied event with detailed context"""
        event_data = {
            'resource': resource,
            'action': action,
            'user_role': user.role.name if hasattr(user, 'role') and user.role else None,
        }
        
        description = f"Permission denied for user {user.email if user else 'anonymous'} accessing {resource} ({action})"
        
        return self.log_security_event(
            request=request,
            event_type='permission_denied',
            event_data=event_data,
            severity='medium',
            user=user,
            description=description
        )
    
    def log_suspicious_activity(self, request, activity_type: str, details: Dict[str, Any]):
        """Log suspicious activity with risk assessment"""
        event_data = {
            'activity_type': activity_type,
            'details': details,
        }
        
        # Determine severity based on activity type
        high_risk_activities = ['sql_injection', 'xss_attempt', 'path_traversal', 'command_injection']
        critical_activities = ['privilege_escalation', 'data_exfiltration', 'malware_upload']
        
        if activity_type in critical_activities:
            severity = 'critical'
        elif activity_type in high_risk_activities:
            severity = 'high'
        else:
            severity = 'medium'
        
        description = f"Suspicious activity detected: {activity_type}"
        
        return self.log_security_event(
            request=request,
            event_type='suspicious_activity',
            event_data=event_data,
            severity=severity,
            description=description
        )
    
    def log_file_upload_threat(self, request, filename: str, threat_type: str, details: str):
        """Log file upload threat detection"""
        event_data = {
            'filename': filename,
            'threat_type': threat_type,
            'details': details,
        }
        
        # Determine severity based on threat type
        severity = 'critical' if threat_type == 'malware' else 'high'
        
        description = f"File upload threat detected: {threat_type} in {filename}"
        
        return self.log_security_event(
            request=request,
            event_type='file_upload_threat',
            event_data=event_data,
            severity=severity,
            description=description
        )
    
    def log_rate_limit_exceeded(self, request, limit_type: str, limit_value: int):
        """Log rate limit exceeded event"""
        event_data = {
            'limit_type': limit_type,
            'limit_value': limit_value,
        }
        
        description = f"Rate limit exceeded: {limit_type} (limit: {limit_value})"
        
        return self.log_security_event(
            request=request,
            event_type='rate_limit_exceeded',
            event_data=event_data,
            severity='medium',
            description=description
        )
    
    def log_session_event(self, request, session_action: str, session_data: Dict[str, Any] = None):
        """Log session-related security events"""
        event_type = f'session_{session_action}'
        
        event_data = session_data or {}
        
        description = f"Session {session_action}"
        
        severity = 'low' if session_action == 'created' else 'medium'
        
        return self.log_security_event(
            request=request,
            event_type=event_type,
            event_data=event_data,
            severity=severity,
            description=description
        )
    
    def log_data_access(self, request, resource: str, action: str, record_count: int = None):
        """Log data access events for audit trails"""
        event_data = {
            'resource': resource,
            'action': action,
        }
        
        if record_count is not None:
            event_data['record_count'] = record_count
        
        description = f"Data access: {action} on {resource}"
        if record_count:
            description += f" ({record_count} records)"
        
        # Higher severity for bulk data access
        severity = 'high' if record_count and record_count > 100 else 'low'
        
        return self.log_security_event(
            request=request,
            event_type='data_access',
            event_data=event_data,
            severity=severity,
            description=description
        )
    
    def log_admin_action(self, request, action: str, target: str, details: Dict[str, Any] = None):
        """Log administrative actions"""
        event_data = {
            'action': action,
            'target': target,
            'details': details or {},
        }
        
        description = f"Admin action: {action} on {target}"
        
        # Higher severity for sensitive admin actions
        sensitive_actions = ['delete_user', 'change_permissions', 'system_config', 'data_export']
        severity = 'high' if action in sensitive_actions else 'medium'
        
        return self.log_security_event(
            request=request,
            event_type='admin_action',
            event_data=event_data,
            severity=severity,
            description=description
        )
    
    def _generate_description(self, event_type: str, event_data: Dict[str, Any]) -> str:
        """Generate human-readable description for event"""
        descriptions = {
            'authentication_attempt': 'Authentication attempt',
            'authentication_success': 'Successful authentication',
            'authentication_failure': 'Failed authentication',
            'permission_denied': 'Permission denied',
            'suspicious_activity': 'Suspicious activity detected',
            'file_upload_threat': 'File upload threat detected',
            'rate_limit_exceeded': 'Rate limit exceeded',
            'session_created': 'Session created',
            'session_terminated': 'Session terminated',
            'data_access': 'Data access',
            'admin_action': 'Administrative action',
        }
        
        base_description = descriptions.get(event_type, f'Security event: {event_type}')
        
        # Add context from event_data if available
        if event_data:
            if 'user_identifier' in event_data:
                base_description += f" for {event_data['user_identifier']}"
            elif 'resource' in event_data:
                base_description += f" on {event_data['resource']}"
            elif 'activity_type' in event_data:
                base_description += f": {event_data['activity_type']}"
        
        return base_description
    
    def _get_log_level(self, severity: str) -> int:
        """Convert severity to logging level"""
        levels = {
            'low': logging.INFO,
            'medium': logging.WARNING,
            'high': logging.ERROR,
            'critical': logging.CRITICAL,
        }
        return levels.get(severity, logging.WARNING)
    
    def _get_client_ip(self, request) -> str:
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip


# Global security event logger instance
security_event_logger = SecurityEventLogger()


def log_security_event(request, event_type: str, **kwargs):
    """Convenient function for logging security events"""
    return security_event_logger.log_security_event(request, event_type, **kwargs)


def log_authentication_attempt(request, user_identifier: str, success: bool, **kwargs):
    """Convenient function for logging authentication attempts"""
    return security_event_logger.log_authentication_attempt(request, user_identifier, success, **kwargs)


def log_suspicious_activity(request, activity_type: str, details: Dict[str, Any]):
    """Convenient function for logging suspicious activities"""
    return security_event_logger.log_suspicious_activity(request, activity_type, details)
