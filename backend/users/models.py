from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin, BaseUserManager
from django.core.validators import RegexValidator
import uuid



# Manager for CustomUser
class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user



#Custom user model
class CustomUser(AbstractUser):
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
    username = None
    REQUIRED_FIELDS = [] 
    
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