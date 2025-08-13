"""
Merged User Model Template
Combines Frontend_PRS compatibility with Backend_PRS-1 advanced features
"""

from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from deals.validators import validate_file_security

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
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['status']),
        ]


class UserSession(models.Model):
    """
    Stores active user sessions for tracking and management.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, unique=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email}'s session from {self.ip_address}"


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
