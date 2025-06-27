from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from organization.models import Organization
from permissions.models import Role as OrgRole
# from team.models import Team # This is removed to prevent circular import

class User(AbstractUser):
    """
    Custom user model with roles and organization linkage.
    """
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
    org_role = models.ForeignKey(OrgRole, on_delete=models.SET_NULL, null=True, blank=True)
    contact_number = models.CharField(max_length=20, blank=True, null=True)
    team = models.ForeignKey('team.Team', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_users')

    def __str__(self):
        return self.username


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
        return f"{self.user.username}'s session from {self.ip_address}"
