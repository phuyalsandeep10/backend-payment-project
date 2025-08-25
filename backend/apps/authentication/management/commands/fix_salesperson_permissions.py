from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from apps.permissions.models import Role
from apps.authentication.models import User

class Command(BaseCommand):
    help = 'Fix missing permissions for Salesperson role'

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("=== Fixing Salesperson Permissions ==="))
        
        # Get all Salesperson roles
        salesperson_roles = Role.objects.filter(name='Salesperson')
        
        if not salesperson_roles.exists():
            self.stdout.write(self.style.WARNING("No Salesperson roles found!"))
            return
        
        # Define permissions that salespersons should have for deals
        permission_codenames = [
            # Deal permissions
            'view_all_deals',
            'view_own_deals', 
            'create_deal',
            'edit_deal',
            'delete_deal',
            'log_deal_activity',
            
            # Client permissions
            'view_all_clients',
            'view_own_clients',
            'create_new_client',
            'edit_client_details',
            'remove_client',
            
            # Team permissions
            'view_all_teams',
            'view_own_teams',
            'create_new_team',
            'edit_team_details',
            'remove_team',
            
            # Commission permissions
            'view_all_commissions',
            'create_commission',
            'edit_commission',
            
            # Project permissions
            'view_all_projects',
            'view_own_projects',
            'create_project',
            'edit_project',
            
            # Standard Django permissions
            'view_client',
            'add_client', 
            'change_client',
            'delete_client',
            'view_deal',
            'add_deal',
            'change_deal',
            'delete_deal',
            'view_project',
            'add_project',
            'change_project',
            'delete_project',
            'view_team',
            'add_team',
            'change_team',
            'delete_team',
            'view_commission',
            'add_commission',
            'change_commission',
            'delete_commission',
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