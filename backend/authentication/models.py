from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from organization.models import Organization
from permissions.models import Role
# from team.models import Team # This is removed to prevent circular import

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
    Custom user model with roles and organization linkage.
    """
    # Use email as the primary identifier
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField('email address', unique=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    contact_number = models.CharField(max_length=20, blank=True, null=True)
    team = models.ForeignKey('team.Team', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_users')

    objects = CustomUserManager()

    def __str__(self):
        return self.email


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
