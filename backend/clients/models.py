from django.db import models
from django.core.validators import RegexValidator

# Create your models here.
class Clients(models.Model):
    SATISFACTION_CHOICES = [
        ('excellent', 'Excellent'),
        ('good', 'Good'),
        ('average', 'Average'),
        ('poor', 'Poor'),
    ]
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('prospect', 'Prospect'),
    ]
    client_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, validators=[RegexValidator(r'^\+?\d{10,15}$', 'Enter a valid phone number')],)
    nationality = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    remarks = models.TextField(blank=True, null=True)
    satisfaction = models.CharField(max_length=255,choices=SATISFACTION_CHOICES,blank=True, null=True)
    status = models.CharField(max_length=255,choices=STATUS_CHOICES,blank=True, null=True)
    
    class Meta:
        ordering = ["client_name"]
        verbose_name = ("Client")
        verbose_name_plural = ("Clients") 
        
    def __str__(self):
        return self.client_name