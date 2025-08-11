from django.db import models
from django.core.validators import RegexValidator
from django.conf import settings
from organization.models import Organization

# Create your models here.
class Client(models.Model):
    SATISFACTION_CHOICES = [
        ('neutral', 'Neutral'),
        ('satisfied', 'Satisfied'),
        ('unsatisfied', 'Un-Satisfied'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('bad_debt', 'Bad Debt'),
        ('clear', 'Clear'),
    ]
    client_name = models.CharField(max_length=255, db_index=True)
    email = models.EmailField(db_index=True)
    phone_number = models.CharField(max_length=30, validators=[RegexValidator(r'^\+?\d{10,15}$', 'Enter a valid phone number.')],)
    nationality = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    remarks = models.TextField(blank=True, null=True)
    satisfaction = models.CharField(max_length=20, choices=SATISFACTION_CHOICES, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, blank=True, null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='clients_created')
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='clients_updated')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='clients', db_index=True)
    
    class Meta:
        ordering = ["client_name"]
        verbose_name = ("Client")
        verbose_name_plural = ("Clients")
        unique_together = ('email', 'organization')
        indexes = [
            models.Index(fields=['organization', 'created_by']),
            models.Index(fields=['status']),
        ]
        permissions = [
            ("view_all_clients", "Can view all clients"),
            ("view_own_clients", "Can view own clients"),
            ("create_new_client", "Can create a new client"),
            ("edit_client_details", "Can edit client details"),
            ("remove_client", "Can delete a client"),
        ]
        
    def __str__(self):
        return self.client_name