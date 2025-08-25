from django.core.management.base import BaseCommand
from django.db import transaction
from apps.permissions.models import Role, Permission
from apps.organization.models import Organization


class Command(BaseCommand):
    help = 'Create default roles for all organizations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--organization',
            type=int,
            help='Create roles for specific organization ID',
        )

    def handle(self, *args, **options):
        org_id = options.get('organization')
        
        if org_id:
            try:
                organizations = [Organization.objects.get(id=org_id)]
                self.stdout.write(f'Creating roles for organization ID: {org_id}')
            except Organization.DoesNotExist:
                self.stderr.write(f'Organization with ID {org_id} does not exist')
                return
        else:
            organizations = Organization.objects.all()
            self.stdout.write('Creating roles for all organizations')

        default_roles = [
            {
                'name': 'Org Admin',
                'permissions': ['create_user', 'view_user', 'edit_user', 'delete_user', 'manage_roles']
            },
            {
                'name': 'Salesperson',
                'permissions': ['create_deal_payment']
            },
            {
                'name': 'Verifier',
                'permissions': ['verify_deal_payment']
            },
            {
                'name': 'Supervisor',
                'permissions': ['view_user']
            },
            {
                'name': 'Team Member',
                'permissions': []
            }
        ]

        with transaction.atomic():
            for org in organizations:
                self.stdout.write(f'Processing organization: {org.name}')
                
                for role_data in default_roles:
                    role, created = Role.objects.get_or_create(
                        name=role_data['name'],
                        organization=org,
                        defaults={}
                    )
                    
                    if created:
                        self.stdout.write(f'  Created role: {role_data["name"]}')
                        
                        # Add permissions
                        if role_data['permissions']:
                            try:
                                permissions = Permission.objects.filter(
                                    codename__in=role_data['permissions']
                                )
                                role.permissions.set(permissions)
                                self.stdout.write(f'    Added {permissions.count()} permissions')
                            except Permission.DoesNotExist:
                                self.stdout.write(f'    Some permissions not found, skipping')
                    else:
                        self.stdout.write(f'  Role already exists: {role_data["name"]}')

        self.stdout.write(self.style.SUCCESS('Successfully created default roles')) 