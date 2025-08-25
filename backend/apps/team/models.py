from django.db import models
from apps.project.models import Project
from django.conf import settings
from apps.organization.models import Organization

# Create your models here.
class Team(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name='teams')
    team_lead = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='led_teams')
    members = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='teams', blank=True)
    projects = models.ManyToManyField(Project, related_name='teams', blank=True)
    contact_number = models.CharField(max_length=20, blank=True, null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_teams')
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='updated_teams')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        permissions = [
            ("view_all_teams", "Can view all teams"),
            ("view_own_teams", "Can view own teams"),
            ("create_new_team", "Can create a new team"),
            ("edit_team_details", "Can edit team details"),
            ("remove_team", "Can delete a team"),
        ]

    def __str__(self):
        return self.name
