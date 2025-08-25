"""
Security Models - Task 2.2.1

Security-related models moved from core_config for better organization.
Provides comprehensive security event logging and audit trail functionality.
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
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    # Status choices
    STATUS_CHOICES = [
        ('NEW', 'New'),
        ('INVESTIGATING', 'Investigating'),
        ('RESOLVED', 'Resolved'),
        ('FALSE_POSITIVE', 'False Positive'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='NEW')
    
    # User and session info
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    session_key = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Event details
    description = models.TextField()
    event_data = models.JSONField(default=dict, blank=True)
    risk_score = models.IntegerField(default=0)  # 0-100
    
    # Geographic info
    country = models.CharField(max_length=2, blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Investigation fields
    investigated_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, 
        null=True, blank=True, 
        related_name='investigated_security_events'
    )
    investigation_notes = models.TextField(blank=True)
    resolution_action = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['event_type', 'created_at']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['ip_address', 'created_at']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['risk_score']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.severity} - {self.created_at}"
    
    def save(self, *args, **kwargs):
        # Auto-calculate risk score based on severity and event type
        if not self.risk_score:
            self.risk_score = self._calculate_risk_score()
        super().save(*args, **kwargs)
    
    def _calculate_risk_score(self):
        """Calculate risk score based on event type and severity"""
        base_scores = {
            'sql_injection_attempt': 95,
            'intrusion_detected': 90,
            'malware_detected': 85,
            'brute_force_detected': 80,
            'xss_attempt': 75,
            'permission_escalation': 70,
            'authentication_failure': 30,
            'suspicious_activity': 50,
            'rate_limit_exceeded': 25,
        }
        
        severity_multipliers = {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.6,
            'LOW': 0.4,
        }
        
        base_score = base_scores.get(self.event_type, 40)
        multiplier = severity_multipliers.get(self.severity, 0.6)
        
        return int(base_score * multiplier)
    
    def is_critical(self):
        """Check if this is a critical security event"""
        critical_events = [
            'sql_injection_attempt', 'intrusion_detected', 'malware_detected',
            'brute_force_detected', 'permission_escalation'
        ]
        return self.event_type in critical_events or self.severity == 'CRITICAL'
    
    def get_related_events(self, hours=24):
        """Get related security events from the same IP or user"""
        from datetime import timedelta
        
        time_threshold = timezone.now() - timedelta(hours=hours)
        
        # Find events from same IP or user
        filters = models.Q(created_at__gte=time_threshold)
        
        if self.user:
            filters &= models.Q(user=self.user)
        
        if self.ip_address:
            filters |= models.Q(ip_address=self.ip_address)
        
        return SecurityEvent.objects.filter(filters).exclude(pk=self.pk)


class SecurityAlert(models.Model):
    """
    Model for managing security alerts and notifications
    """
    
    ALERT_TYPES = [
        ('SECURITY_EVENT', 'Security Event Alert'),
        ('THRESHOLD_BREACH', 'Threshold Breach'),
        ('PATTERN_DETECTION', 'Suspicious Pattern Detection'),
        ('COMPLIANCE_VIOLATION', 'Compliance Violation'),
        ('SYSTEM_ANOMALY', 'System Anomaly'),
    ]
    
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('ACKNOWLEDGED', 'Acknowledged'),
        ('RESOLVED', 'Resolved'),
        ('SUPPRESSED', 'Suppressed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    
    title = models.CharField(max_length=255)
    description = models.TextField()
    alert_data = models.JSONField(default=dict, blank=True)
    
    # Related security events
    related_events = models.ManyToManyField(SecurityEvent, blank=True)
    
    # Assignment and resolution
    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, 
        null=True, blank=True,
        related_name='assigned_security_alerts'
    )
    acknowledged_by = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='acknowledged_security_alerts'
    )
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='resolved_security_alerts'
    )
    
    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Escalation settings
    escalation_level = models.IntegerField(default=0)
    auto_escalate = models.BooleanField(default=True)
    escalation_threshold_hours = models.IntegerField(default=24)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['alert_type', 'created_at']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['assigned_to', 'status']),
        ]
    
    def __str__(self):
        return f"{self.alert_type} - {self.severity} - {self.status}"
    
    def acknowledge(self, user):
        """Acknowledge the alert"""
        self.status = 'ACKNOWLEDGED'
        self.acknowledged_by = user
        self.acknowledged_at = timezone.now()
        self.save()
    
    def resolve(self, user, resolution_notes=None):
        """Resolve the alert"""
        self.status = 'RESOLVED'
        self.resolved_by = user
        self.resolved_at = timezone.now()
        if resolution_notes:
            self.alert_data['resolution_notes'] = resolution_notes
        self.save()
    
    def escalate(self):
        """Escalate the alert"""
        self.escalation_level += 1
        if self.severity == 'LOW':
            self.severity = 'MEDIUM'
        elif self.severity == 'MEDIUM':
            self.severity = 'HIGH'
        elif self.severity == 'HIGH':
            self.severity = 'CRITICAL'
        self.save()


class ComplianceReport(models.Model):
    """
    Model for compliance reporting and audit trails
    """
    
    REPORT_TYPES = [
        ('SECURITY_AUDIT', 'Security Audit'),
        ('ACCESS_LOG', 'Access Log Report'),
        ('DATA_PROTECTION', 'Data Protection Compliance'),
        ('GDPR_COMPLIANCE', 'GDPR Compliance Report'),
        ('SOX_COMPLIANCE', 'SOX Compliance Report'),
        ('CUSTOM', 'Custom Compliance Report'),
    ]
    
    STATUS_CHOICES = [
        ('GENERATING', 'Generating'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('ARCHIVED', 'Archived'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='GENERATING')
    
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    # Report parameters
    report_parameters = models.JSONField(default=dict, blank=True)
    report_data = models.JSONField(default=dict, blank=True)
    
    # Time range
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    
    # Report generation
    generated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # File storage
    report_file = models.FileField(upload_to='compliance_reports/', null=True, blank=True)
    file_size = models.BigIntegerField(null=True, blank=True)
    file_hash = models.CharField(max_length=64, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['report_type', 'created_at']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['generated_by', 'created_at']),
            models.Index(fields=['start_date', 'end_date']),
        ]
    
    def __str__(self):
        return f"{self.report_type} - {self.title} - {self.status}"