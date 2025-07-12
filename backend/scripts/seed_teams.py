#!/usr/bin/env python
"""Seed sample teams for organisation Brahmabytelab.
Run with:
    python manage.py shell < backend/scripts/seed_teams.py
Creates 5 teams if they don't already exist.
"""
import django
django.setup()

from organization.models import Organization
from permissions.models import Role
from authentication.models import User
from team.models import Team
from project.models import Project

ORG_NAME = "Brahmabytelab"
TEAM_COUNT = 5

org = Organization.objects.filter(name__iexact=ORG_NAME).first()
if not org:
    raise SystemExit(f"Organisation '{ORG_NAME}' not found. Seed it first.")

supervisor_role = Role.objects.filter(name__iexact='supervisor', organization=org).first()
member_role = Role.objects.filter(name__iexact='team-member', organization=org).first()

if not supervisor_role or not member_role:
    raise SystemExit("Required roles not found. Seed users first.")

supervisors = list(User.objects.filter(role=supervisor_role))
members = list(User.objects.filter(role=member_role))
projects = list(Project.objects.all()[:TEAM_COUNT])

if not supervisors or len(members) < 2:
    raise SystemExit("Not enough supervisors or team members to create teams.")

for i in range(1, TEAM_COUNT + 1):
    team_name = f"Auto Team {i}"
    team, created = Team.objects.get_or_create(name=team_name, organization=org,
                                               defaults={
                                                   'team_lead': supervisors[(i-1) % len(supervisors)],
                                                   'contact_number': '+977-9800000000'
                                               })
    if created:
        # add members and projects
        team.members.set(members[(i-1)*2:(i-1)*2+3])
        if projects:
            team.projects.add(projects[(i-1) % len(projects)])
        team.save()
        print("Created team", team_name)
    else:
        print("Team already exists:", team_name)

print("Team seeding completed.") 