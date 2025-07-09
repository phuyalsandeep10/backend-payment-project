"""
Merged User Model Template
Combines Frontend_PRS compatibility with Backend_PRS-1 advanced features
"""

from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator

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
        ('invited', 'Invited'),
        ('suspended', 'Suspended'),
    ]
    
    # Use email as the primary identifier
    username = models.CharField(max_length=150, unique=False, blank=True)
    email = models.EmailField('email address', unique=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # Relationships
    organization = models.ForeignKey('organization.Organization', on_delete=models.SET_NULL, null=True, blank=True)
    role = models.ForeignKey('permissions.Role', on_delete=models.SET_NULL, null=True, blank=True)
    team = models.ForeignKey('team.Team', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_users')
    
    # Contact information
    contact_number = models.CharField(max_length=30, blank=True, null=True)
    address = models.TextField(blank=True, null=True, help_text="User's address")
    
    # Frontend compatibility fields
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    avatar = models.URLField(blank=True, null=True, help_text="URL to user's avatar image")
    must_change_password = models.BooleanField(default=False, help_text="Require user to change password at next login")
    
    # Advanced features
    sales_target = models.DecimalField(max_digits=15, decimal_places=2, null=True, default=None)
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


class UserProfile(models.Model):
    """
    Stores user profile information, including profile picture.
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    bio = models.TextField(blank=True, null=True, max_length=500)

    def __str__(self):
        return f'{self.user.username} Profile'
