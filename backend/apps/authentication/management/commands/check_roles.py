from django.core.management.base import BaseCommand
from apps.organization.models import Organization
from apps.permissions.models import Role

class Command(BaseCommand):
    help = 'Check roles in the database and verify Organization Admin roles exist'

    def handle(self, *args, **options):
        self.stdout.write("=== Database Role Check ===")
        
        # Check all organizations
        organizations = Organization.objects.all()
        self.stdout.write(f"Total Organizations: {organizations.count()}")
        
        for org in organizations:
            self.stdout.write(f"\n--- Organization: {org.name} (ID: {org.id}) ---")
            
            # Get roles for this organization
            org_roles = Role.objects.filter(organization=org)
            self.stdout.write(f"  Roles: {org_roles.count()}")
            
            for role in org_roles:
                self.stdout.write(f"    - {role.name} (ID: {role.id})")
            
            # Check specifically for Organization Admin role
            org_admin_role = Role.objects.filter(name="Organization Admin", organization=org).first()
            if org_admin_role:
                self.stdout.write(f"  ✅ Organization Admin role found: {org_admin_role.id}")
            else:
                self.stdout.write(f"  ❌ Organization Admin role NOT found!")
                
                # Try to create it
                try:
                    new_role = Role.objects.create(name="Organization Admin", organization=org)
                    self.stdout.write(f"  🔧 Created Organization Admin role: {new_role.id}")
                except Exception as e:
                    self.stdout.write(f"  ❌ Failed to create role: {e}")
        
        # Check for any roles without organizations (system-wide roles)
        system_roles = Role.objects.filter(organization__isnull=True)
        self.stdout.write(f"\n--- System-wide Roles ---")
        self.stdout.write(f"Total: {system_roles.count()}")
        
        for role in system_roles:
            self.stdout.write(f"  - {role.name} (ID: {role.id})")
        
        self.stdout.write("\n=== Role Check Complete ===")
