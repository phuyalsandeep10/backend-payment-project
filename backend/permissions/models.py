from django.db import models
from organization.models import Organization

class Permission(models.Model):
    """
    Model to represent a specific, granular permission in the system.
    e.g., "View All Clients", "Create Client".
    """
    name = models.CharField(max_length=255)
    codename = models.CharField(max_length=100, unique=True)
    category = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class Role(models.Model):
    """
    Model to represent a role within a specific organization.
    e.g., "Salesperson" for "CG Group Pvt.Ltd".
    """
    name = models.CharField(max_length=100)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name='roles', null=True, blank=True)
    permissions = models.ManyToManyField(Permission, blank=True)

    class Meta:
        unique_together = ('name', 'organization')

    def __str__(self):
        if self.organization:
            return f"{self.name} ({self.organization.name})"
        return f"{self.name} (System Role)"
