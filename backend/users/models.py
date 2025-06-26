from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin, BaseUserManager
from django.core.validators import RegexValidator
import uuid



# Manager for CustomUser
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        
        return self.create_user(email, password, **extra_fields)

#Custom user model
class CustomUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True, help_text="UUID for the user, used as primary key for security.")
    email = models.EmailField(unique=True)
    username = None # this is done so that we can use email field as the username field if not it raises an error
        
    full_name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)

    phone_number = models.CharField(max_length=20, validators=[RegexValidator(r'^\+?\d{10,15}$', 'Enter a valid phone number')],)
    address = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    zip_code = models.CharField(max_length=10, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    
    # this is for later when roles and teams section is done
    # role =  models.ForeignKey(Role, null=True, blank=True, on_delete=models.SET_NULL, related_name='users')
    # team =  models.ForeignKey(Team, null=True, blank=True, on_delete=models.SET_NULL, related_name='users', blank = True, null = True)
        
    # custom usermanager as we are using email as username field and need to make it compulsory
    objects = CustomUserManager()
    USERNAME_FIELD = 'email'
    
    def __str__(self):
        return self.email

    def soft_delete(self):
        """
        Soft delete this user (deactivate account).
        """
        self.is_active = False
        self.save()    
        
    class Meta:
        ordering = ["email"]
        verbose_name = ('user')
        verbose_name_plural = ('users')