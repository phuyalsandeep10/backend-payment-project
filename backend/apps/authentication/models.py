"""
Merged User Model Template
Combines Frontend_PRS compatibility with Backend_PRS-1 advanced features
"""

from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from apps.deals.validators import validate_file_security

class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """
    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        # Set username to email if not provided
        if 'username' not in extra_fields:
            extra_fields['username'] = email
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        # For superuser, username must be set. We can use email.
        if 'username' not in extra_fields:
            extra_fields['username'] = email
            
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Enhanced user model with frontend compatibility and advanced features.
    """
    # Frontend compatibility: Status choices
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('pending', 'Pending'),  # Frontend compatibility
        ('invited', 'Invited'),
        ('suspended', 'Suspended'),
    ]
    
    # Use email as the primary identifier
    username = models.CharField(max_length=150, unique=False, blank=True)
    email = models.EmailField('email address', unique=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # Relationships
    organization = models.ForeignKey(
        'organization.Organization',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='users',
        db_index=True
    )
    role = models.ForeignKey(
        'permissions.Role', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        db_index=True,
        related_name='users'
    )
    team = models.ForeignKey('team.Team', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_users')
    
    # Contact information
    contact_number = models.CharField(max_length=30, blank=True, null=True)
    address = models.TextField(blank=True, null=True, help_text="User's address")

    # Frontend compatibility fields
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    must_change_password = models.BooleanField(default=False, help_text="Require user to change password at next login")
    login_count = models.IntegerField(default=0)

    # Advanced features
    sales_target = models.DecimalField(max_digits=15, decimal_places=2, default=0.0)
    streak = models.FloatField(default=5.0, validators=[MinValueValidator(0.0), MaxValueValidator(5.0)])

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    # Frontend compatibility properties
    @property
    def name(self):
        """Combined name property to match frontend expectations"""
        return f"{self.first_name} {self.last_name}".strip() or self.username

    @property
    def phone_number(self):
        """Alias for contact_number to match frontend expectations"""
        return self.contact_number

    @property
    def phoneNumber(self):
        """Alternative alias for contact_number"""
        return self.contact_number

    class Meta:
        indexes = [
            # Existing indexes
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['status']),
            
            # Enhanced organization-scoped query optimization
            models.Index(fields=['organization', 'role']),
            models.Index(fields=['organization', 'is_active']),
            models.Index(fields=['organization', 'date_joined']),
            models.Index(fields=['organization', 'last_login']),
            
            # Role-based filtering optimization
            models.Index(fields=['role', 'is_active']),
            models.Index(fields=['role', 'organization']),
            
            # Performance critical composite indexes for common queries
            models.Index(fields=['organization', 'status', 'is_active']),
            models.Index(fields=['organization', 'role', 'status']),
            
            # Email lookup optimization (already unique but helps with joins)
            models.Index(fields=['email', 'is_active']),
            
            # Team-based queries optimization
            models.Index(fields=['team', 'organization']),
            
            # Login tracking optimization
            models.Index(fields=['login_count', 'organization']),
            models.Index(fields=['must_change_password', 'organization']),
            
            # Additional strategic indexes for performance optimization
            models.Index(fields=['is_active', 'last_login', 'organization']),
            models.Index(fields=['role', 'status', 'date_joined']),
            models.Index(fields=['organization', 'sales_target', 'is_active']),
            models.Index(fields=['streak', 'organization', 'role']),
            models.Index(fields=['organization', 'username', 'is_active']),
            models.Index(fields=['date_joined', 'organization', 'is_active']),
        ]


class UserSession(models.Model):
    """
    Stores active user sessions for tracking and management.
    Enhanced with activity tracking and expiration management.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, unique=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-last_activity']

    def __str__(self):
        return f"{self.user.email}'s session from {self.ip_address}"
    
    def is_expired(self):
        """Check if the session has expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    def update_activity(self):
        """Update the last activity timestamp"""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])
    
    def set_expiry(self, hours=24):
        """Set session expiry time (default 24 hours from now)"""
        self.expires_at = timezone.now() + timezone.timedelta(hours=hours)
        self.save(update_fields=['expires_at'])


class SecureUserSession(models.Model):
    """
    Enhanced secure user session model with comprehensive security features
    """
    # Session identification
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='secure_sessions')
    session_id = models.CharField(max_length=128, unique=True, db_index=True)
    jwt_token_id = models.CharField(max_length=128, db_index=True, help_text="JWT token ID (jti claim)")
    
    # Session metadata
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    
    # Client information
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField()
    user_agent_hash = models.CharField(max_length=64, db_index=True)
    session_fingerprint = models.CharField(max_length=64, db_index=True)
    
    # Security features
    login_method = models.CharField(max_length=20, default='jwt', db_index=True)
    device_type = models.CharField(max_length=50, blank=True, null=True)
    browser_name = models.CharField(max_length=50, blank=True, null=True)
    os_name = models.CharField(max_length=50, blank=True, null=True)
    
    # Security flags
    is_suspicious = models.BooleanField(default=False, db_index=True)
    suspicious_reason = models.CharField(max_length=200, blank=True, null=True)
    flagged_at = models.DateTimeField(blank=True, null=True)
    
    # Session hijacking protection
    ip_verified = models.BooleanField(default=True)
    user_agent_verified = models.BooleanField(default=True)
    fingerprint_verified = models.BooleanField(default=True)
    
    # Additional metadata
    login_location = models.CharField(max_length=100, blank=True, null=True)
    timezone = models.CharField(max_length=50, blank=True, null=True)
    
    class Meta:
        indexes = [
            # Primary lookup indexes
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['session_id']),
            models.Index(fields=['jwt_token_id']),
            
            # Security monitoring indexes
            models.Index(fields=['ip_address', 'created_at']),
            models.Index(fields=['user_agent_hash']),
            models.Index(fields=['session_fingerprint']),
            models.Index(fields=['is_suspicious', 'created_at']),
            
            # Cleanup and maintenance indexes
            models.Index(fields=['expires_at']),
            models.Index(fields=['last_activity']),
            models.Index(fields=['is_active', 'expires_at']),
            
            # Analytics indexes
            models.Index(fields=['login_method', 'created_at']),
            models.Index(fields=['device_type', 'created_at']),
            models.Index(fields=['browser_name', 'created_at']),
        ]
        
        ordering = ['-created_at']
        verbose_name = 'Secure User Session'
        verbose_name_plural = 'Secure User Sessions'
    
    def __str__(self):
        return f"{self.user.email}'s session from {self.ip_address} ({self.session_id[:8]}...)"
    
    def is_expired(self):
        """Check if session is expired"""
        from django.utils import timezone
        return timezone.now() > self.expires_at
    
    def mark_suspicious(self, reason: str):
        """Mark session as suspicious"""
        from django.utils import timezone
        self.is_suspicious = True
        self.suspicious_reason = reason
        self.flagged_at = timezone.now()
        self.save(update_fields=['is_suspicious', 'suspicious_reason', 'flagged_at'])
    
    def invalidate(self, reason: str = 'user_action'):
        """Invalidate the session"""
        self.is_active = False
        self.save(update_fields=['is_active'])
        
        # Log the invalidation
        import logging
        logger = logging.getLogger('security')
        logger.info(f"Session invalidated for {self.user.email}: {self.session_id[:8]}... (reason: {reason})")
    
    def update_activity(self):
        """Update last activity timestamp"""
        from django.utils import timezone
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])
    
    def get_session_info(self):
        """Get safe session information for client"""
        return {
            'session_id': self.session_id[:8] + '...',
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'ip_address': self.ip_address,
            'device_type': self.device_type,
            'browser_name': self.browser_name,
            'os_name': self.os_name,
            'login_method': self.login_method,
            'is_current': False,  # This would be set by the calling code
        }
    
    @classmethod
    def cleanup_expired_sessions(cls):
        """Clean up expired sessions"""
        from django.utils import timezone
        expired_count = cls.objects.filter(
            expires_at__lt=timezone.now()
        ).update(is_active=False)
        
        return expired_count
    
    @classmethod
    def get_user_active_sessions(cls, user):
        """Get all active sessions for a user"""
        return cls.objects.filter(
            user=user,
            is_active=True,
            expires_at__gt=timezone.now()
        ).order_by('-last_activity')
    
    @classmethod
    def enforce_session_limit(cls, user, max_sessions=5):
        """Enforce maximum session limit for user"""
        active_sessions = cls.get_user_active_sessions(user)
        
        if active_sessions.count() >= max_sessions:
            # Deactivate oldest sessions
            excess_sessions = active_sessions[max_sessions-1:]
            for session in excess_sessions:
                session.invalidate('session_limit_exceeded')
            
            return excess_sessions.count()
        
        return 0


class SecurityEvent(models.Model):
    """
    Comprehensive security event logging model for audit trails
    """
    # Event types
    EVENT_TYPE_CHOICES = [
        ('authentication_attempt', 'Authentication Attempt'),
        ('authentication_success', 'Authentication Success'),
        ('authentication_failure', 'Authentication Failure'),
        ('permission_denied', 'Permission Denied'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('file_upload_threat', 'File Upload Threat'),
        ('rate_limit_exceeded', 'Rate Limit Exceeded'),
        ('session_created', 'Session Created'),
        ('session_terminated', 'Session Terminated'),
        ('password_changed', 'Password Changed'),
        ('account_locked', 'Account Locked'),
        ('account_unlocked', 'Account Unlocked'),
        ('data_access', 'Data Access'),
        ('data_modification', 'Data Modification'),
        ('admin_action', 'Admin Action'),
        ('security_violation', 'Security Violation'),
        ('malware_detected', 'Malware Detected'),
        ('intrusion_attempt', 'Intrusion Attempt'),
        ('privilege_escalation', 'Privilege Escalation'),
        ('data_export', 'Data Export'),
    ]
    
    # Severity levels
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    # Core fields
    event_type = models.CharField(max_length=30, choices=EVENT_TYPE_CHOICES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium', db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    
    # User information
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='security_events'
    )
    user_email = models.EmailField(blank=True, null=True)  # Store email even if user is deleted
    user_role = models.CharField(max_length=50, blank=True, null=True)
    
    # Request context
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField(blank=True, null=True)
    user_agent_hash = models.CharField(max_length=64, blank=True, null=True, db_index=True)
    request_path = models.CharField(max_length=500, blank=True, null=True)
    request_method = models.CharField(max_length=10, blank=True, null=True)
    
    # Event details
    event_description = models.TextField()
    event_data = models.JSONField(default=dict, blank=True)  # Additional structured data
    
    # Geographic information (optional)
    country = models.CharField(max_length=2, blank=True, null=True)  # ISO country code
    city = models.CharField(max_length=100, blank=True, null=True)
    
    # Response information
    response_status = models.IntegerField(blank=True, null=True)
    response_time_ms = models.IntegerField(blank=True, null=True)
    
    # Correlation and tracking
    correlation_id = models.CharField(max_length=36, blank=True, null=True, db_index=True)
    session_id = models.CharField(max_length=128, blank=True, null=True, db_index=True)
    
    # Risk assessment
    risk_score = models.IntegerField(default=0, db_index=True)  # 0-100 risk score
    is_blocked = models.BooleanField(default=False, db_index=True)
    
    # Investigation status
    is_investigated = models.BooleanField(default=False, db_index=True)
    investigated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='investigated_events'
    )
    investigated_at = models.DateTimeField(blank=True, null=True)
    investigation_notes = models.TextField(blank=True, null=True)
    
    class Meta:
        indexes = [
            # Primary lookup indexes
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            
            # Security monitoring indexes
            models.Index(fields=['risk_score', 'timestamp']),
            models.Index(fields=['is_blocked', 'timestamp']),
            models.Index(fields=['user_agent_hash', 'timestamp']),
            models.Index(fields=['correlation_id']),
            
            # Investigation indexes
            models.Index(fields=['is_investigated', 'timestamp']),
            models.Index(fields=['investigated_by', 'investigated_at']),
            
            # Analytics indexes
            models.Index(fields=['event_type', 'severity', 'timestamp']),
            models.Index(fields=['country', 'timestamp']),
            models.Index(fields=['session_id', 'timestamp']),
        ]
        
        ordering = ['-timestamp']
        verbose_name = 'Security Event'
        verbose_name_plural = 'Security Events'
    
    def __str__(self):
        return f"{self.event_type} - {self.severity} - {self.timestamp}"
    
    def save(self, *args, **kwargs):
        # Auto-populate user information if user is provided
        if self.user and not self.user_email:
            self.user_email = self.user.email
            if hasattr(self.user, 'role') and self.user.role:
                self.user_role = self.user.role.name
        
        # Generate correlation ID if not provided
        if not self.correlation_id:
            import uuid
            self.correlation_id = str(uuid.uuid4())
        
        # Hash user agent if provided
        if self.user_agent and not self.user_agent_hash:
            import hashlib
            self.user_agent_hash = hashlib.sha256(self.user_agent.encode()).hexdigest()
        
        super().save(*args, **kwargs)
    
    def mark_investigated(self, investigator, notes=None):
        """Mark event as investigated"""
        from django.utils import timezone
        self.is_investigated = True
        self.investigated_by = investigator
        self.investigated_at = timezone.now()
        if notes:
            self.investigation_notes = notes
        self.save(update_fields=['is_investigated', 'investigated_by', 'investigated_at', 'investigation_notes'])
    
    def calculate_risk_score(self):
        """Calculate risk score based on event characteristics"""
        score = 0
        
        # Base score by event type
        high_risk_events = ['intrusion_attempt', 'privilege_escalation', 'malware_detected', 'security_violation']
        medium_risk_events = ['suspicious_activity', 'file_upload_threat', 'authentication_failure']
        
        if self.event_type in high_risk_events:
            score += 50
        elif self.event_type in medium_risk_events:
            score += 25
        else:
            score += 10
        
        # Severity multiplier
        severity_multipliers = {'low': 1.0, 'medium': 1.5, 'high': 2.0, 'critical': 3.0}
        score = int(score * severity_multipliers.get(self.severity, 1.0))
        
        # Recent similar events increase score
        recent_events = SecurityEvent.objects.filter(
            ip_address=self.ip_address,
            event_type=self.event_type,
            timestamp__gte=timezone.now() - timezone.timedelta(hours=1)
        ).count()
        
        if recent_events > 1:
            score += min(recent_events * 10, 30)  # Cap at 30 additional points
        
        # Cap at 100
        self.risk_score = min(score, 100)
        return self.risk_score
    
    @classmethod
    def get_security_dashboard_data(cls, days=7):
        """Get security dashboard data for the last N days"""
        from django.utils import timezone
        from django.db.models import Count, Q
        
        start_date = timezone.now() - timezone.timedelta(days=days)
        
        events = cls.objects.filter(timestamp__gte=start_date)
        
        return {
            'total_events': events.count(),
            'critical_events': events.filter(severity='critical').count(),
            'high_risk_events': events.filter(risk_score__gte=70).count(),
            'blocked_events': events.filter(is_blocked=True).count(),
            'uninvestigated_events': events.filter(is_investigated=False, severity__in=['high', 'critical']).count(),
            
            'events_by_type': dict(events.values('event_type').annotate(count=Count('id')).values_list('event_type', 'count')),
            'events_by_severity': dict(events.values('severity').annotate(count=Count('id')).values_list('severity', 'count')),
            'events_by_day': list(events.extra({'day': 'date(timestamp)'}).values('day').annotate(count=Count('id')).order_by('day')),
            
            'top_ips': list(events.values('ip_address').annotate(count=Count('id')).order_by('-count')[:10]),
            'top_users': list(events.filter(user__isnull=False).values('user__email').annotate(count=Count('id')).order_by('-count')[:10]),
            
            'authentication_failures': events.filter(event_type='authentication_failure').count(),
            'suspicious_activities': events.filter(event_type='suspicious_activity').count(),
            'malware_detections': events.filter(event_type='malware_detected').count(),
        }
    
    @classmethod
    def cleanup_old_events(cls, days=90):
        """Clean up old security events (keep for 90 days by default)"""
        from django.utils import timezone
        
        cutoff_date = timezone.now() - timezone.timedelta(days=days)
        deleted_count = cls.objects.filter(timestamp__lt=cutoff_date).delete()[0]
        
        return deleted_count


class OTPToken(models.Model):
    """
    Enhanced OTP token model with comprehensive security features
    """
    # OTP purposes
    PURPOSE_CHOICES = [
        ('login', 'Login Verification'),
        ('password_reset', 'Password Reset'),
        ('email_verification', 'Email Verification'),
        ('admin_action', 'Admin Action Verification'),
        ('sensitive_operation', 'Sensitive Operation'),
    ]
    
    # Core fields
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='otp_tokens')
    token = models.CharField(max_length=10)  # Store plain token temporarily
    token_hash = models.CharField(max_length=64, db_index=True)  # SHA256 hash for security
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, db_index=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    
    # Security and rate limiting
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=3)
    is_used = models.BooleanField(default=False, db_index=True)
    is_locked = models.BooleanField(default=False, db_index=True)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    # Request context for security
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent_hash = models.CharField(max_length=64, null=True, blank=True)
    
    # Delivery tracking
    delivery_method = models.CharField(max_length=20, default='email')
    delivery_status = models.CharField(max_length=20, default='pending')
    delivery_attempts = models.IntegerField(default=0)
    last_delivery_attempt = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        indexes = [
            # Primary lookup indexes
            models.Index(fields=['user', 'purpose', 'is_used']),
            models.Index(fields=['token_hash']),
            models.Index(fields=['expires_at']),
            
            # Security monitoring indexes
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['ip_address', 'created_at']),
            models.Index(fields=['is_locked', 'locked_until']),
            
            # Rate limiting indexes
            models.Index(fields=['user', 'purpose', 'created_at']),
            models.Index(fields=['attempts', 'max_attempts']),
        ]
        
        ordering = ['-created_at']
        verbose_name = 'OTP Token'
        verbose_name_plural = 'OTP Tokens'
    
    def __str__(self):
        return f"OTP for {self.user.email} ({self.purpose}) - {'Used' if self.is_used else 'Active'}"
    
    def save(self, *args, **kwargs):
        # Hash the token before saving
        if self.token and not self.token_hash:
            import hashlib
            self.token_hash = hashlib.sha256(self.token.encode()).hexdigest()
        super().save(*args, **kwargs)
    
    def is_expired(self):
        """Check if OTP is expired"""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if OTP is valid (not used, not expired, not locked)"""
        return (
            not self.is_used and 
            not self.is_expired() and 
            not self.is_locked and
            (not self.locked_until or timezone.now() > self.locked_until)
        )
    
    def verify_token(self, provided_token: str, request=None) -> bool:
        """
        Verify the provided token against this OTP
        
        Args:
            provided_token: Token provided by user
            request: HTTP request for security context
            
        Returns:
            bool: True if token is valid and matches
        """
        # Check if OTP is valid
        if not self.is_valid():
            return False
        
        # Increment attempt counter
        self.attempts += 1
        
        # Check if max attempts exceeded
        if self.attempts >= self.max_attempts:
            self.is_locked = True
            self.locked_until = timezone.now() + timezone.timedelta(minutes=15)  # 15 minute lockout
            self.save(update_fields=['attempts', 'is_locked', 'locked_until'])
            return False
        
        # Verify token hash
        import hashlib
        provided_hash = hashlib.sha256(provided_token.encode()).hexdigest()
        
        if provided_hash == self.token_hash:
            # Token matches - mark as used
            self.is_used = True
            self.used_at = timezone.now()
            
            # Store request context if provided
            if request:
                self.ip_address = self._get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                if user_agent:
                    self.user_agent_hash = hashlib.sha256(user_agent.encode()).hexdigest()
            
            self.save(update_fields=['attempts', 'is_used', 'used_at', 'ip_address', 'user_agent_hash'])
            return True
        else:
            # Token doesn't match - save attempt count
            self.save(update_fields=['attempts'])
            return False
    
    def mark_delivery_attempt(self, status='sent'):
        """Mark a delivery attempt"""
        self.delivery_attempts += 1
        self.delivery_status = status
        self.last_delivery_attempt = timezone.now()
        self.save(update_fields=['delivery_attempts', 'delivery_status', 'last_delivery_attempt'])
    
    def _get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip
    
    @classmethod
    def cleanup_expired_tokens(cls):
        """Clean up expired and used tokens"""
        expired_count = cls.objects.filter(
            expires_at__lt=timezone.now()
        ).delete()[0]
        
        # Also clean up old used tokens (older than 24 hours)
        old_used_count = cls.objects.filter(
            is_used=True,
            used_at__lt=timezone.now() - timezone.timedelta(hours=24)
        ).delete()[0]
        
        return expired_count + old_used_count
    
    @classmethod
    def get_user_rate_limit_status(cls, user, purpose, time_window_minutes=60):
        """
        Check rate limit status for user and purpose
        
        Args:
            user: User instance
            purpose: OTP purpose
            time_window_minutes: Time window for rate limiting
            
        Returns:
            dict: Rate limit status information
        """
        time_threshold = timezone.now() - timezone.timedelta(minutes=time_window_minutes)
        
        recent_tokens = cls.objects.filter(
            user=user,
            purpose=purpose,
            created_at__gte=time_threshold
        )
        
        total_attempts = recent_tokens.count()
        failed_attempts = recent_tokens.filter(is_used=False).count()
        locked_tokens = recent_tokens.filter(is_locked=True).count()
        
        return {
            'total_attempts': total_attempts,
            'failed_attempts': failed_attempts,
            'locked_tokens': locked_tokens,
            'is_rate_limited': total_attempts >= 5,  # Max 5 OTPs per hour
            'next_allowed_at': None  # Could implement more sophisticated rate limiting
        }


class PasswordHistory(models.Model):
    """
    Stores password history for users to prevent password reuse
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='password_history')
    password_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'created_at']),
        ]
        ordering = ['-created_at']
        verbose_name = 'Password History'
        verbose_name_plural = 'Password Histories'
    
    def __str__(self):
        return f"Password history for {self.user.email} at {self.created_at}"


class PasswordExpiration(models.Model):
    """
    Tracks password expiration and notifications for users
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='password_expiration')
    password_changed_at = models.DateTimeField(default=timezone.now)
    expiration_notified_at = models.DateTimeField(null=True, blank=True)
    warning_sent_count = models.IntegerField(default=0)
    is_expired = models.BooleanField(default=False)
    
    class Meta:
        indexes = [
            models.Index(fields=['password_changed_at']),
            models.Index(fields=['is_expired']),
        ]
        verbose_name = 'Password Expiration'
        verbose_name_plural = 'Password Expirations'
    
    def __str__(self):
        return f"Password expiration for {self.user.email}"
    
    def update_password_changed(self):
        """Update password change timestamp"""
        self.password_changed_at = timezone.now()
        self.is_expired = False
        self.warning_sent_count = 0
        self.expiration_notified_at = None
        self.save()


class UserProfile(models.Model):
    """
    Stores user profile information, including profile picture.
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    profile_picture = models.ImageField(
        upload_to='profile_pics/', 
        null=True, 
        blank=True,
        validators=[validate_file_security]
    )
    bio = models.TextField(blank=True, null=True, max_length=500)

    def __str__(self):
        return f'{self.user.username} Profile'
