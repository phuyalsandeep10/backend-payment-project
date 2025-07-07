from django.db import models
from django.core.validators import RegexValidator
from django.conf import settings
from organization.models import Organization
from django.utils import timezone

# Create your models here.
class Client(models.Model):
    # Categories to match frontend expectations
    CATEGORY_CHOICES = [
        ('loyal', 'Loyal'),
        ('inconsistent', 'Inconsistent'),
        ('occasional', 'Occasional'),
    ]
    
    SATISFACTION_CHOICES = [
        ('excellent', 'Excellent'),
        ('good', 'Good'),
        ('average', 'Average'),
        ('poor', 'Poor'),
        # Legacy choices for backward compatibility
        ('positive', 'Positive'),
        ('neutral', 'Neutral'),
        ('negative', 'Negative'),
    ]
    
    STATUS_CHOICES = [
        ('clear', 'Clear'),
        ('pending', 'Pending'),
        ('bad_debt', 'Bad Debt'),
        # Legacy choices for backward compatibility
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('prospect', 'Prospect'),
    ]
    
    # Core fields
    client_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, validators=[RegexValidator(r'^\+?\d{10,15}$', 'Enter a valid phone number')])
    
    # Frontend expected fields
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='occasional')
    salesperson = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_clients')
    teams = models.ManyToManyField('team.Team', blank=True, related_name='clients')
    last_contact = models.DateTimeField(null=True, blank=True)
    expected_close = models.DateField(null=True, blank=True)
    value = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, null=True, blank=True)
    satisfaction = models.CharField(max_length=20, choices=SATISFACTION_CHOICES, null=True, blank=True)
    
    # Contact details
    primary_contact_name = models.CharField(max_length=255, blank=True, null=True)
    primary_contact_phone = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    
    # Additional fields
    nationality = models.CharField(max_length=100, blank=True, null=True)
    remarks = models.TextField(blank=True, null=True)
    avatar_url = models.URLField(blank=True, null=True)
    
    # Metadata
    active_date = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='clients')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='clients')
    
    class Meta:
        ordering = ["client_name"]
        verbose_name = ("Client")
        verbose_name_plural = ("Clients") 
        
    def __str__(self):
        return self.client_name

    @property
    def name(self):
        """Alias for client_name to match frontend expectations"""
        return self.client_name


class ClientActivity(models.Model):
    """
    Model for client-specific activities
    """
    TYPE_CHOICES = [
        ('meeting', 'Meeting'),
        ('call', 'Call'),
        ('email', 'Email'),
        ('note', 'Note'),
    ]
    
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='activities')
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='note')
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.client.client_name} - {self.type} - {self.timestamp}"