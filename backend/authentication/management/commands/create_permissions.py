from django.core.management.base import BaseCommand
from permissions.models import Permission, Role

class Command(BaseCommand):
    help = 'Create custom permissions and assign them to roles'

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("=== Creating Custom Permissions ==="))
        
        # Define permissions
        permissions_data = [
            # Client permissions
            {'name': 'View All Clients', 'codename': 'view_all_clients', 'category': 'clients'},
            {'name': 'View Own Clients', 'codename': 'view_own_clients', 'category': 'clients'},
            {'name': 'Create Client', 'codename': 'create_client', 'category': 'clients'},
            {'name': 'Edit Client Details', 'codename': 'edit_client_details', 'category': 'clients'},
            {'name': 'Delete Client', 'codename': 'delete_client', 'category': 'clients'},
            
            # Deal permissions
            {'name': 'View All Deals', 'codename': 'view_all_deals', 'category': 'deals'},
            {'name': 'View Own Deals', 'codename': 'view_own_deals', 'category': 'deals'},
            {'name': 'Create Deal', 'codename': 'create_deal', 'category': 'deals'},
            {'name': 'Edit Own Deals', 'codename': 'edit_own_deals', 'category': 'deals'},
            {'name': 'Edit All Deals', 'codename': 'edit_all_deals', 'category': 'deals'},
            {'name': 'Delete Deal', 'codename': 'delete_deal', 'category': 'deals'},
            {'name': 'Verify Deals', 'codename': 'verify_deals', 'category': 'deals'},
            
            # Project permissions
            {'name': 'View All Projects', 'codename': 'view_all_projects', 'category': 'projects'},
            {'name': 'View Own Projects', 'codename': 'view_own_projects', 'category': 'projects'},
            {'name': 'Create Project', 'codename': 'create_project', 'category': 'projects'},
            {'name': 'Edit Own Projects', 'codename': 'edit_own_projects', 'category': 'projects'},
            {'name': 'Edit All Projects', 'codename': 'edit_all_projects', 'category': 'projects'},
            {'name': 'Delete Project', 'codename': 'delete_project', 'category': 'projects'},
            
            # Team permissions
            {'name': 'View All Teams', 'codename': 'view_all_teams', 'category': 'teams'},
            {'name': 'View Own Team', 'codename': 'view_own_team', 'category': 'teams'},
            {'name': 'Create Team', 'codename': 'create_team', 'category': 'teams'},
            {'name': 'Edit Team', 'codename': 'edit_team', 'category': 'teams'},
            {'name': 'Delete Team', 'codename': 'delete_team', 'category': 'teams'},
            
            # Dashboard permissions
            {'name': 'View Dashboard', 'codename': 'view_dashboard', 'category': 'dashboard'},
            {'name': 'View Own Performance', 'codename': 'view_own_performance', 'category': 'dashboard'},
            {'name': 'View Team Performance', 'codename': 'view_team_performance', 'category': 'dashboard'},
            {'name': 'View Organization Performance', 'codename': 'view_org_performance', 'category': 'dashboard'},
            
            # Commission permissions
            {'name': 'View Own Commission', 'codename': 'view_own_commission', 'category': 'commission'},
            {'name': 'View All Commission', 'codename': 'view_all_commission', 'category': 'commission'},
            {'name': 'Create Commission', 'codename': 'create_commission', 'category': 'commission'},
            {'name': 'Edit Commission', 'codename': 'edit_commission', 'category': 'commission'},
        ]
        
        # Create permissions
        created_count = 0
        for perm_data in permissions_data:
            permission, created = Permission.objects.get_or_create(
                codename=perm_data['codename'],
                defaults={
                    'name': perm_data['name'],
                    'category': perm_data['category']
                }
            )
            if created:
                created_count += 1
                self.stdout.write(f"  ✅ Created permission: {permission.name}")
        
        self.stdout.write(self.style.SUCCESS(f"Created {created_count} new permissions"))
        
        # Assign permissions to roles
        self.assign_permissions_to_roles()
        
        self.stdout.write(self.style.SUCCESS("✅ Permissions created and assigned successfully!"))
    
    def assign_permissions_to_roles(self):
        self.stdout.write(self.style.HTTP_INFO("--- Assigning Permissions to Roles ---"))
        
        # Define role permissions
        role_permissions = {
            'Salesperson': [
                'view_own_clients', 'create_client', 'edit_client_details',
                'view_own_deals', 'create_deal', 'edit_own_deals',
                'view_own_projects', 'create_project', 'edit_own_projects',
                'view_own_team', 'view_dashboard', 'view_own_performance',
                'view_own_commission'
            ],
            'Senior Salesperson': [
                'view_all_clients', 'create_client', 'edit_client_details',
                'view_all_deals', 'create_deal', 'edit_own_deals',
                'view_all_projects', 'create_project', 'edit_own_projects',
                'view_all_teams', 'view_dashboard', 'view_own_performance',
                'view_team_performance', 'view_own_commission'
            ],
            'Sales Manager': [
                'view_all_clients', 'create_client', 'edit_client_details', 'delete_client',
                'view_all_deals', 'create_deal', 'edit_all_deals', 'delete_deal',
                'view_all_projects', 'create_project', 'edit_all_projects', 'delete_project',
                'view_all_teams', 'create_team', 'edit_team',
                'view_dashboard', 'view_own_performance', 'view_team_performance',
                'view_org_performance', 'view_all_commission', 'create_commission', 'edit_commission'
            ],
            'Verifier': [
                'view_all_clients', 'view_all_deals', 'verify_deals',
                'view_all_projects', 'view_dashboard', 'view_org_performance'
            ],
            'Organization Admin': [
                # All permissions
                'view_all_clients', 'create_client', 'edit_client_details', 'delete_client',
                'view_all_deals', 'create_deal', 'edit_all_deals', 'delete_deal', 'verify_deals',
                'view_all_projects', 'create_project', 'edit_all_projects', 'delete_project',
                'view_all_teams', 'create_team', 'edit_team', 'delete_team',
                'view_dashboard', 'view_own_performance', 'view_team_performance', 'view_org_performance',
                'view_all_commission', 'create_commission', 'edit_commission'
            ]
        }
        
        for role_name, permission_codenames in role_permissions.items():
            roles = Role.objects.filter(name=role_name)
            permissions = Permission.objects.filter(codename__in=permission_codenames)
            
            for role in roles:
                role.permissions.set(permissions)
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  ✅ Assigned {permissions.count()} permissions to {role.name} "
                        f"({role.organization or 'Template'})"
                    )
                ) 