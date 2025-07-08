from django.db import models
from organization.models import Organization
from django.contrib.auth.models import Permission

class Role(models.Model):
    """
    Defines a role within an organization, which is a collection of permissions.
    e.g., "Salesperson" for "CG Group Pvt.Ltd".
    """
    name = models.CharField(max_length=100)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='roles', null=True, blank=True)
    permissions = models.ManyToManyField(Permission, blank=True)

    class Meta:
        unique_together = ('name', 'organization')

    def __str__(self):
        if self.organization:
            return f"{self.name} ({self.organization.name})"
        return f"{self.name} (System Role)"
