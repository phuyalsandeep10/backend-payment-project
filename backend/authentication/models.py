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
