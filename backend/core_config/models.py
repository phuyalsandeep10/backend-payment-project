"""
Security and Audit Models
Provides comprehensive security event logging and audit trail functionality
"""

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
import json
import uuid

User = get_user_model()


class SecurityEvent(models.Model):
    """
    Model for logging security-related events
    """
    
    # Event types
    EVENT_TYPES = [
        ('authentication_attempt', 'Authentication Attempt'),
        ('authentication_success', 'Authentication Success'),
        ('authentication_failure', 'Authentication Failed'),
        ('authorization_failure', 'Authorization Failed'),
        ('password_change', 'Password Change'),
        ('password_reset', 'Password Reset'),
        ('account_lockout', 'Account Lockout'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('file_upload', 'File Upload'),
        ('file_upload_blocked', 'File Upload Blocked'),
        ('rate_limit_exceeded', 'Rate Limit Exceeded'),
        ('session_created', 'Session Created'),
        ('session_expired', 'Session Expired'),
        ('session_terminated', 'Session Terminated'),
        ('permission_escalation', 'Permission Escalation Attempt'),
        ('data_access', 'Sensitive Data Access'),
        ('configuration_change', 'Configuration Change'),
        ('security_scan_detected', 'Security Scan Detected'),
        ('brute_force_detected', 'Brute Force Attack Detected'),
        ('sql_injection_attempt', 'SQL Injection Attempt'),
        ('xss_attempt', 'XSS Attempt'),
        ('csrf_violation', 'CSRF Violation'),
        ('malware_detected', 'Malware Detected'),
        ('intrusion_detected', 'Intrusion Detected'),
    ]
    
    # Severity levels
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    # Core fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='medium', db_index=True)
    
    # User and session information
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, db_index=True)
    session_id = models.CharField(max_length=128, null=True, blank=True)
    
    # Request information
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField(blank=True)
    request_path = models.CharField(max_length=500, blank=True)
    request_method = models.CharField(max_length=10, blank=True)
    request_id = models.CharField(max_length=128, null=True, blank=True)
    
    # Event details
    event_data = models.JSONField(default=dict, blank=True)
    message = models.TextField(blank=True)
    
    # Metadata
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    source = models.CharField(max_length=100, default='application')  # application, middleware, etc.
    
    # Geolocation (optional)
    country = models.CharField(max_length=2, blank=True)  # ISO country code
    city = models.CharField(max_length=100, blank=True)
    
    # Risk assessment
    risk_score = models.IntegerField(default=0)  # 0-100 risk score
    is_blocked = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'security_events'
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['timestamp', 'event_type']),
            models.Index(fields=['risk_score', 'timestamp']),
            models.Index(fields=['is_blocked', 'timestamp']),
        ]
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.event_type} - {self.ip_address} - {self.timestamp}"
    
    @classmethod
    def log_event(cls, event_type, ip_address, user=None, severity='medium', 
                  message='', event_data=None, request=None, risk_score=0):
        """
        Convenience method to log security events
        """
        event_data = event_data or {}
        
        # Extract request information if provided
        request_path = ''
        request_method = ''
        user_agent = ''
        session_id = ''
        request_id = ''
        
        if request:
            request_path = request.path
            request_method = request.method
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:1000]  # Truncate
            session_id = request.session.session_key or ''
            request_id = getattr(request, 'request_id', '')
            
            # Use request user if not provided
            if not user and hasattr(request, 'user') and request.user.is_authenticated:
                user = request.user
        
        return cls.objects.create(
            event_type=event_type,
            severity=severity,
            user=user,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_path=request_path,
            request_method=request_method,
            request_id=request_id,
            event_data=event_data,
            message=message,
            risk_score=risk_score
        )
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': str(self.id),
            'event_type': self.event_type,
            'severity': self.severity,
            'user_id': self.user.id if self.user else None,
            'username': self.user.username if self.user else None,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'request_path': self.request_path,
            'request_method': self.request_method,
            'event_data': self.event_data,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'risk_score': self.risk_score,
            'is_blocked': self.is_blocked,
        }


class AuditTrail(models.Model):
    """
    Model for comprehensive audit trails of data changes
    """
    
    # Action types
    ACTION_TYPES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('VIEW', 'View'),
        ('EXPORT', 'Export'),
        ('IMPORT', 'Import'),
        ('APPROVE', 'Approve'),
        ('REJECT', 'Reject'),
        ('ARCHIVE', 'Archive'),
        ('RESTORE', 'Restore'),
    ]
    
    # Core fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # What was changed
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.CharField(max_length=100, db_index=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Action details
    action = models.CharField(max_length=20, choices=ACTION_TYPES, db_index=True)
    table_name = models.CharField(max_length=100, db_index=True)
    
    # Data changes
    old_values = models.JSONField(null=True, blank=True)
    new_values = models.JSONField(null=True, blank=True)
    changed_fields = models.JSONField(default=list, blank=True)  # List of changed field names
    
    # Who made the change
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, db_index=True)
    session_id = models.CharField(max_length=128, null=True, blank=True)
    
    # When and where
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Request context
    request_id = models.CharField(max_length=128, null=True, blank=True)
    request_path = models.CharField(max_length=500, blank=True)
    request_method = models.CharField(max_length=10, blank=True)
    
    # Additional metadata
    reason = models.TextField(blank=True)  # Reason for change
    is_sensitive = models.BooleanField(default=False)  # Mark sensitive data changes
    retention_period = models.IntegerField(default=2555)  # Days to retain (default 7 years)
    
    class Meta:
        db_table = 'audit_trails'
        indexes = [
            models.Index(fields=['content_type', 'object_id']),
            models.Index(fields=['table_name', 'object_id']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['timestamp', 'table_name']),
            models.Index(fields=['is_sensitive', 'timestamp']),
        ]
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.action} {self.table_name}:{self.object_id} by {self.user} at {self.timestamp}"
    
    @classmethod
    def log_change(cls, instance, action, user=None, old_values=None, new_values=None, 
                   request=None, reason='', is_sensitive=False):
        """
        Log a data change to the audit trail
        """
        content_type = ContentType.objects.get_for_model(instance)
        table_name = instance._meta.db_table
        
        # Extract request information
        ip_address = None
        user_agent = ''
        session_id = ''
        request_id = ''
        request_path = ''
        request_method = ''
        
        if request:
            ip_address = cls._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:1000]
            session_id = request.session.session_key or ''
            request_id = getattr(request, 'request_id', '')
            request_path = request.path
            request_method = request.method
            
            # Use request user if not provided
            if not user and hasattr(request, 'user') and request.user.is_authenticated:
                user = request.user
        
        # Determine changed fields
        changed_fields = []
        if old_values and new_values:
            changed_fields = [
                field for field in new_values.keys()
                if field in old_values and old_values[field] != new_values[field]
            ]
        
        return cls.objects.create(
            content_type=content_type,
            object_id=str(instance.pk),
            action=action,
            table_name=table_name,
            old_values=old_values,
            new_values=new_values,
            changed_fields=changed_fields,
            user=user,
            session_id=session_id,
            timestamp=timezone.now(),
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            request_path=request_path,
            request_method=request_method,
            reason=reason,
            is_sensitive=is_sensitive
        )
    
    @staticmethod
    def _get_client_ip(request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': str(self.id),
            'content_type': str(self.content_type),
            'object_id': self.object_id,
            'action': self.action,
            'table_name': self.table_name,
            'old_values': self.old_values,
            'new_values': self.new_values,
            'changed_fields': self.changed_fields,
            'user_id': self.user.id if self.user else None,
            'username': self.user.username if self.user else None,
            'timestamp': self.timestamp.isoformat(),
            'ip_address': self.ip_address,
            'request_path': self.request_path,
            'request_method': self.request_method,
            'reason': self.reason,
            'is_sensitive': self.is_sensitive,
        }


class SecurityAlert(models.Model):
    """
    Model for security alerts and notifications
    """
    
    ALERT_TYPES = [
        ('brute_force', 'Brute Force Attack'),
        ('suspicious_login', 'Suspicious Login'),
        ('multiple_failures', 'Multiple Authentication Failures'),
        ('unusual_activity', 'Unusual Activity Pattern'),
        ('malware_detected', 'Malware Detected'),
        ('data_breach_attempt', 'Data Breach Attempt'),
        ('privilege_escalation', 'Privilege Escalation'),
        ('account_compromise', 'Account Compromise'),
        ('system_intrusion', 'System Intrusion'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES, db_index=True)
    severity = models.CharField(max_length=20, choices=SecurityEvent.SEVERITY_LEVELS, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open', db_index=True)
    
    # Alert details
    title = models.CharField(max_length=200)
    description = models.TextField()
    
    # Related events
    security_events = models.ManyToManyField(SecurityEvent, blank=True)
    
    # Affected entities
    affected_users = models.ManyToManyField(User, blank=True)
    affected_ips = models.JSONField(default=list, blank=True)
    
    # Timestamps
    first_seen = models.DateTimeField(db_index=True)
    last_seen = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Assignment
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, 
                                   related_name='assigned_security_alerts')
    
    # Metrics
    event_count = models.IntegerField(default=1)
    risk_score = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'security_alerts'
        indexes = [
            models.Index(fields=['alert_type', 'status']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['created_at', 'status']),
            models.Index(fields=['risk_score', 'status']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.alert_type} - {self.severity} - {self.status}"


class ComplianceReport(models.Model):
    """
    Model for compliance and audit reports
    """
    
    REPORT_TYPES = [
        ('security_events', 'Security Events Report'),
        ('audit_trail', 'Audit Trail Report'),
        ('access_report', 'Access Report'),
        ('financial_audit', 'Financial Audit Report'),
        ('compliance_check', 'Compliance Check Report'),
        ('user_activity', 'User Activity Report'),
        ('data_access', 'Data Access Report'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('generating', 'Generating'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES, db_index=True)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    
    # Report parameters
    date_from = models.DateTimeField(db_index=True)
    date_to = models.DateTimeField(db_index=True)
    filters = models.JSONField(default=dict, blank=True)
    
    # Generation details
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', db_index=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Report data
    report_data = models.JSONField(null=True, blank=True)
    file_path = models.CharField(max_length=500, blank=True)  # Path to generated file
    
    # Metadata
    record_count = models.IntegerField(default=0)
    file_size = models.IntegerField(default=0)  # Size in bytes
    
    class Meta:
        db_table = 'compliance_reports'
        indexes = [
            models.Index(fields=['report_type', 'status']),
            models.Index(fields=['created_by', 'created_at']),
            models.Index(fields=['date_from', 'date_to']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.report_type} - {self.created_at}"