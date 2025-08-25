"""
Django Management Command: Setup Super Admin
Robust super admin creation and verification with field compatibility
"""
from django.core.management.base import BaseCommand
from django.conf import settings
from apps.authentication.models import User
from apps.permissions.models import Role

class Command(BaseCommand):
    help = 'Creates a new super admin user if one does not already exist.'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, help='Super admin email (default from settings)')
        parser.add_argument('--password', type=str, help='Super admin password (default from settings)')
        parser.add_argument('--username', type=str, help='Super admin username (default from settings)')

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('--- Checking for existing Super Admin ---'))

        # Check if a super admin already exists
        existing_superadmin = User.objects.filter(is_superuser=True).first()
        if existing_superadmin:
            self.stdout.write(self.style.WARNING(f'A super admin already exists with the email: {existing_superadmin.email}'))
            self.stdout.write(self.style.WARNING('No new super admin was created.'))
            return

        self.stdout.write(self.style.SUCCESS('No existing super admin found. Proceeding with creation...'))

        admin_email = (
            options.get('email')
            or getattr(settings, 'ADMIN_EMAIL', None)
            or f"{getattr(settings, 'ADMIN_USER', 'admin')}@innovate.com"
        )
        admin_password = options.get('password') or getattr(settings, 'ADMIN_PASS', None)
        admin_username = options.get('username') or getattr(settings, 'ADMIN_USER', 'admin')

        if not admin_password:
            self.stdout.write(self.style.ERROR('A password must be provided via the --password argument or ADMIN_PASS setting.'))
            return

        try:
            # Ensure the Super Admin role exists (matching initialize_app)
            super_admin_role, created = Role.objects.get_or_create(name='Super Admin')
            if created:
                self.stdout.write(self.style.SUCCESS('Created "Super Admin" role.'))

            # Create the superuser first
            superuser = User.objects.create_superuser(
                email=admin_email,
                username=admin_username,
                password=admin_password
            )
            
            # Then assign the role
            superuser.role = super_admin_role
            superuser.save()
            
            self.stdout.write(self.style.SUCCESS(f'Successfully created super admin: {admin_email}'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'An error occurred during super admin creation: {e}'))