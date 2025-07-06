from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from permissions.models import Role

class Command(BaseCommand):
    help = 'Fix missing permissions for Salesperson role'

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("=== Fixing Salesperson Permissions ==="))
        
        # Get all Salesperson roles
        salesperson_roles = Role.objects.filter(name='Salesperson')
        
        if not salesperson_roles.exists():
            self.stdout.write(self.style.WARNING("No Salesperson roles found!"))
            return
        
        # Define permissions that salespersons should have
        permission_codenames = [
            'view_client',
            'add_client', 
            'change_client',
            'view_deal',
            'add_deal',
            'change_deal',
            'view_project'
        ]
        
        # Get Permission objects
        permissions = Permission.objects.filter(codename__in=permission_codenames)
        
        self.stdout.write(f"Found {permissions.count()} permissions to add")
        
        # Add permissions to all Salesperson roles
        for role in salesperson_roles:
            for perm in permissions:
                role.permissions.add(perm)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f"✅ Added {permissions.count()} permissions to {role.name} "
                    f"({role.organization or 'Template'})"
                )
            )
        
        self.stdout.write(self.style.SUCCESS("✅ Salesperson permissions fixed successfully!")) 