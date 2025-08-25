from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from apps.organization.models import Organization
from apps.permissions.models import Role

User = get_user_model()

class Command(BaseCommand):
    help = 'Check current users in the database and verify org admins'

    def add_arguments(self, parser):
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed information about each user',
        )

    def handle(self, *args, **options):
        verbose = options['verbose']
        
        self.stdout.write("=== Database User Check ===")
        
        # Check total users
        total_users = User.objects.count()
        self.stdout.write(f"Total Users: {total_users}")
        
        # Check superusers
        superusers = User.objects.filter(is_superuser=True)
        self.stdout.write(f"Superusers: {superusers.count()}")
        
        # Check users with organizations
        org_users = User.objects.filter(organization__isnull=False)
        self.stdout.write(f"Users with Organizations: {org_users.count()}")
        
        # Check users without organizations
        no_org_users = User.objects.filter(organization__isnull=True)
        self.stdout.write(f"Users without Organizations: {no_org_users.count()}")
        
        # Check users with roles
        users_with_roles = User.objects.filter(role__isnull=False)
        self.stdout.write(f"Users with Roles: {users_with_roles.count()}")
        
        # Check users without roles
        users_without_roles = User.objects.filter(role__isnull=True)
        self.stdout.write(f"Users without Roles: {users_without_roles.count()}")
        
        # Check organizations
        organizations = Organization.objects.all()
        self.stdout.write(f"\nTotal Organizations: {organizations.count()}")
        
        for org in organizations:
            self.stdout.write(f"\n--- Organization: {org.name} (ID: {org.id}) ---")
            
            # Get users in this organization
            org_users = User.objects.filter(organization=org)
            self.stdout.write(f"  Users: {org_users.count()}")
            
            # Get roles in this organization
            org_roles = Role.objects.filter(organization=org)
            self.stdout.write(f"  Roles: {org_roles.count()}")
            
            for role in org_roles:
                role_users = User.objects.filter(organization=org, role=role)
                self.stdout.write(f"    {role.name}: {role_users.count()} users")
                
                if verbose:
                    for user in role_users:
                        self.stdout.write(f"      - {user.email} ({user.first_name} {user.last_name}) - Active: {user.is_active}")
        
        # Check for users with 'Organization Admin' role
        org_admin_users = User.objects.filter(role__name='Organization Admin')
        self.stdout.write(f"\nUsers with 'Organization Admin' role: {org_admin_users.count()}")
        
        if verbose:
            for user in org_admin_users:
                org_name = user.organization.name if user.organization else "No Organization"
                self.stdout.write(f"  - {user.email} ({user.first_name} {user.last_name}) - Org: {org_name} - Active: {user.is_active}")
        
        # Check for any users that might be org admins but don't have the role
        potential_org_admins = User.objects.filter(
            organization__isnull=False,
            role__isnull=True
        )
        self.stdout.write(f"\nUsers in organizations but without roles: {potential_org_admins.count()}")
        
        if verbose and potential_org_admins.exists():
            for user in potential_org_admins:
                self.stdout.write(f"  - {user.email} ({user.first_name} {user.last_name}) - Org: {user.organization.name}")
        
        # Summary
        self.stdout.write(f"\n=== Summary ===")
        self.stdout.write(f"Total Users: {total_users}")
        self.stdout.write(f"Users in Organizations: {org_users.count()}")
        self.stdout.write(f"Users with Roles: {users_with_roles.count()}")
        self.stdout.write(f"Organization Admins: {org_admin_users.count()}")
        
        if total_users == 0:
            self.stdout.write(self.style.WARNING("⚠️  No users found in database!"))
        elif org_users.count() == 0:
            self.stdout.write(self.style.WARNING("⚠️  No users are assigned to organizations!"))
        elif users_with_roles.count() == 0:
            self.stdout.write(self.style.WARNING("⚠️  No users have roles assigned!"))
        elif org_admin_users.count() == 0:
            self.stdout.write(self.style.WARNING("⚠️  No organization admins found!"))
        else:
            self.stdout.write(self.style.SUCCESS("✅ Database appears to have users with proper organization and role assignments"))
