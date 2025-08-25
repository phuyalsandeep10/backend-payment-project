"""
Enhanced logging configuration for response validation.
Provides detailed logging for response type validation failures.
"""

import logging
import json
from datetime import datetime
from django.conf import settings

class ResponseValidationLogger:
    """Centralized logger for response validation events."""
    
    def __init__(self):
        self.logger = logging.getLogger('response_validation')
        self.security_logger = logging.getLogger('security')
    
    def log_template_response_conversion(self, view_name, template_name=None):
        """Log when a TemplateResponse is converted to DRF Response."""
        message = f"TemplateResponse converted in {view_name}"
        if template_name:
            message += f" (template: {template_name})"
        
        self.logger.warning(message)
        self.security_logger.warning(f"RESPONSE_VALIDATION: {message}")
    
    def log_http_response_conversion(self, view_name, response_type):
        """Log when an HttpResponse is converted to DRF Response."""
        message = f"HttpResponse ({response_type}) converted in {view_name}"
        self.logger.warning(message)
        self.security_logger.warning(f"RESPONSE_VALIDATION: {message}")
    
    def log_validation_success(self, view_name, response_type):
        """Log successful response validation."""
        message = f"Response validation passed for {view_name}: {response_type}"
        self.logger.debug(message)
    
    def log_validation_error(self, view_name, error):
        """Log response validation errors."""
        message = f"Response validation error in {view_name}: {str(error)}"
        self.logger.error(message)
        self.security_logger.error(f"RESPONSE_VALIDATION_ERROR: {message}")
    
    def log_decorator_application(self, view_name, decorator_name):
        """Log when a response validation decorator is applied."""
        message = f"Applied {decorator_name} to {view_name}"
        self.logger.debug(message)
    
    def generate_validation_report(self, start_time=None, end_time=None):
        """Generate a report of response validation events."""
        # This would typically read from log files or a database
        # For now, return a simple status report
        return {
            'timestamp': datetime.now().isoformat(),
            'status': 'Response validation decorators active',
            'decorators_applied': [
                'validate_response_type',
                'ensure_drf_response', 
                'log_response_type'
            ],
            'critical_endpoints_covered': [
                'login_view',
                'register_view',
                'logout_view',
                'verify_otp_view',
                'super_admin_login_view',
                'super_admin_verify_view',
                'org_admin_login_view',
                'org_admin_verify_view',
                'password_change_view',
                'password_change_with_token_view'
            ]
        }

# Global instance
response_validation_logger = ResponseValidationLogger()

def log_response_validation_event(event_type, view_name, **kwargs):
    """Convenience function to log response validation events."""
    if event_type == 'template_conversion':
        response_validation_logger.log_template_response_conversion(
            view_name, kwargs.get('template_name')
        )
    elif event_type == 'http_conversion':
        response_validation_logger.log_http_response_conversion(
            view_name, kwargs.get('response_type')
        )
    elif event_type == 'validation_success':
        response_validation_logger.log_validation_success(
            view_name, kwargs.get('response_type')
        )
    elif event_type == 'validation_error':
        response_validation_logger.log_validation_error(
            view_name, kwargs.get('error')
        )
    elif event_type == 'decorator_applied':
        response_validation_logger.log_decorator_application(
            view_name, kwargs.get('decorator_name')
        )