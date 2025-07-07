from django.db import models
from django.conf import settings

# Create your models here.
class AuditLogs(models.Model):
    action = models.CharField(max_length=255)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True) 
    details = models.TextField(blank=True, null=True)
    organization = models.ForeignKey(
        'organization.Organization', 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='audit_logs'
    )

    def __str__(self):
        return f"{self.action} by {self.user} on {self.timestamp}"