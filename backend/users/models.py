from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin, BaseUserManager
from django.core.validators import RegexValidator
import uuid
from django.conf import settings 



# Manager for CustomUser
class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(username, email, password, **extra_fields)


#Custom user model
class CustomUser(AbstractUser):
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True, help_text="UUID for the user, used as primary key for security.")
    email = models.EmailField(unique=True)
     # this is done so that we can use email field as the username field if not it raises an error
    
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
    REQUIRED_FIELDS = ['username']
    
   
    
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
        
        
#model to store login info about users
class LoginSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    login_time = models.DateTimeField(auto_now_add=True) 
    session_key = models.CharField(max_length=40,blank=True,null=True) 
    def __str__(self):
        return f"LoginSession(user={self.user.email}, ip={self.ip_address}, time={self.login_time})"