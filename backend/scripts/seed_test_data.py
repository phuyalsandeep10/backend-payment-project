#!/usr/bin/env python
"""Seed test data: 10 team members, 10 supervisors, 10 projects.
Run with:
    $ python manage.py shell < backend/scripts/seed_test_data.py
or convert into a management command.
"""
import os
import django

django.setup()

from django.contrib.auth import get_user_model
from permissions.models import Role
from organization.models import Organization
from project.models import Project

User = get_user_model()

ORG_NAME = "Brahmabytelab"  # target organisation
TEAM_MEMBER_ROLE = "team-member"
SUPERVISOR_ROLE = "supervisor"

# 1. Organisation
org, _ = Organization.objects.get_or_create(name=ORG_NAME)

# 2. Roles
member_role, _ = Role.objects.get_or_create(name=TEAM_MEMBER_ROLE, organization=org)
supervisor_role, _ = Role.objects.get_or_create(name=SUPERVISOR_ROLE, organization=org)

# 3. Users

def create_users(count: int, role: Role, prefix: str):
    existing = User.objects.filter(role=role).count()
    needed = max(0, count - existing)
    for i in range(needed):
        idx = existing + i + 1
        email = f"{prefix}{idx}@example.com"
        if User.objects.filter(email=email).exists():
            continue
        user = User.objects.create_user(
            email=email,
            password="password123",
            first_name=prefix.capitalize(),
            last_name=str(idx),
            username=email,
            organization=org,
            role=role,
        )
        print("Created user", user.email)

create_users(10, supervisor_role, "supervisor")
create_users(10, member_role, "member")

# 4. Projects
existing_projects = Project.objects.count()
for i in range(existing_projects + 1, 11):
    name = f"Project {i}"
    Project.objects.get_or_create(name=name, defaults={"description": "Test project", "created_by": None})
    print("Ensured project", name)

print("Seeding complete.") 