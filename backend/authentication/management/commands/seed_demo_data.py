from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction

from organization.models import Organization
from permissions.models import Role, Permission
from project.models import Project

User = get_user_model()


class Command(BaseCommand):
    help = "Populate the database with demo organization, roles, projects and sample users so that the 'Add Team' form has data to work with.\n\n" \
           "• Creates organisation 'Demo Org' if missing.\n" \
           "• Ensures roles Salesperson, Verifier, Supervisor, Team Member exist (system-wide).\n" \
           "• Seeds 2 users per role with dummy contact numbers.\n" \
           "• Seeds 3 demo projects: Project Alpha/Beta/Gamma.\n" \
           "The command is idempotent – re-running won't create duplicates." 

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("Seeding demo data…"))
        with transaction.atomic():
            # Ensure at least one organization exists
            demo_org, _ = Organization.objects.get_or_create(name="Demo Org", defaults={"is_active": True})
            orgs = list(Organization.objects.all())  # seed users for each org so whichever org-admin you use sees data

            # --- Roles ---
            role_names = [
                "Salesperson",
                "Verifier",
                "Supervisor",  # team lead / supervisor
                "Team Member",
            ]
            roles = {}
            for name in role_names:
                role, _ = Role.objects.get_or_create(name=name, organization=None)
                roles[name] = role
            self.stdout.write(self.style.SUCCESS(f"Ensured roles: {', '.join(role_names)}"))

            # --- Projects ---
            project_names = ["Project Alpha", "Project Beta", "Project Gamma"]
            for pname in project_names:
                Project.objects.get_or_create(name=pname)
            self.stdout.write(self.style.SUCCESS(f"Ensured projects: {', '.join(project_names)}"))

            # --- Users ---
            password = "Password123!"

            def create_demo_user(username, email, first_name, last_name, role_obj, idx):
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        "username": username,
                        "first_name": first_name,
                        "last_name": last_name,
                        "organization": org,
                        "role": role_obj,
                        "contact_number": f"+977-980000{idx:04d}",
                        "is_active": True,
                    },
                )
                if created:
                    user.set_password(password)
                    user.save()
                return created

            created_count = 0
            for org in orgs:
                for role_name, role_obj in roles.items():
                    for i in range(1, 3):  # two users per role per org
                        uname = f"{org.id}_{role_name.lower().replace(' ', '')}{i}"
                        email = f"{uname}@demo.test"
                        fname = role_name.split()[0]
                        lname = f"User{i}"
                        if create_demo_user(uname, email, fname, lname, role_obj, i):
                            user = User.objects.get(email=email)
                            if user.organization_id != org.id:
                                user.organization = org
                                user.save(update_fields=["organization"])
                            created_count += 1

            self.stdout.write(self.style.SUCCESS(f"Created {created_count} users (if they did not already exist)."))

            # --- Teams ---
            from team.models import Team

            teams_created = 0
            for org in orgs:
                # pick one supervisor per org as team lead
                supervisors = User.objects.filter(role=roles['Supervisor'], organization=org)
                if not supervisors.exists():
                    continue
                team_lead = supervisors.first()

                # gather some team members (exclude lead)
                member_pool = User.objects.filter(organization=org).exclude(id=team_lead.id)[:5]
                if not member_pool:
                    continue
                # ensure at least one project exists
                project = Project.objects.first()

                team_name = f"{org.name.split()[0]} Team"
                team, created = Team.objects.get_or_create(
                    name=team_name,
                    organization=org,
                    defaults={
                        "team_lead": team_lead,
                        "contact_number": "+977-1234567890",
                    },
                )
                if created:
                    team.members.set(member_pool)
                    if project:
                        team.projects.set([project])
                    teams_created += 1

            if teams_created:
                self.stdout.write(self.style.SUCCESS(f"Created {teams_created} teams."))
            else:
                self.stdout.write(self.style.WARNING("Teams already exist – no new teams created."))

        self.stdout.write(self.style.SUCCESS("Demo data seeding complete.")) 