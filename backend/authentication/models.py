from django.contrib.auth.models import AbstractUser
from django.db import models
from organization.models import Organization
from permissions.models import Role as OrgRole

class User(AbstractUser):
    """
    Custom user model with roles and organization linkage.
    """
    class Role(models.TextChoices):
        SUPER_ADMIN = 'SUPER_ADMIN', 'Super Admin'
        ORG_ADMIN = 'ORG_ADMIN', 'Organization Admin'
        USER = 'USER', 'User' # General user role

    role = models.CharField(max_length=50, choices=Role.choices, default=Role.USER)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    org_role = models.ForeignKey(OrgRole, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.username
