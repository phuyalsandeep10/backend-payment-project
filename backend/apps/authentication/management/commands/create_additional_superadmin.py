"""
Django Management Command: Create Additional Super Admin
Creates additional super admin users without checking for existing ones
"""
from django.core.management.base import BaseCommand
from django.conf import settings
from apps.authentication.models import User
from apps.permissions.models import Role
import os

class Command(BaseCommand):
    help = 'Creates an additional super admin user with specified credentials.'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, help='Super admin email')
        parser.add_argument('--password', type=str, help='Super admin password')
        parser.add_argument('--username', type=str, help='Super admin username')

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('--- Creating Additional Super Admin ---'))

        # Get credentials from arguments or environment variables
        admin_email = options.get('email') or os.getenv('ADMIN_EMAIL')
        admin_password = options.get('password') or os.getenv('ADMIN_PASS')
        admin_username = options.get('username') or os.getenv('ADMIN_USER')

        if not admin_email:
            self.stdout.write(self.style.ERROR('Email is required. Provide --email argument or set ADMIN_EMAIL in .env'))
            return

        if not admin_password:
            self.stdout.write(self.style.ERROR('Password is required. Provide --password argument or set ADMIN_PASS in .env'))
            return

        if not admin_username:
            admin_username = admin_email.split('@')[0]  # Use email prefix as username

        # Check if user already exists
        if User.objects.filter(email=admin_email).exists():
            self.stdout.write(self.style.WARNING(f'A user with email {admin_email} already exists.'))
            return

        try:
            # Ensure the Super Admin role exists
            super_admin_role, created = Role.objects.get_or_create(name='Super Admin')
            if created:
                self.stdout.write(self.style.SUCCESS('Created "Super Admin" role.'))

            # Create the superuser
            superuser = User.objects.create_superuser(
                email=admin_email,
                username=admin_username,
                password=admin_password
            )
            
            # Assign the role
            superuser.role = super_admin_role
            superuser.is_staff = True
            superuser.save()
            
            self.stdout.write(self.style.SUCCESS(f'✅ Successfully created super admin: {admin_email}'))
            self.stdout.write(self.style.SUCCESS(f'   Username: {admin_username}'))
            self.stdout.write(self.style.SUCCESS(f'   Role: Super Admin'))
            self.stdout.write(self.style.SUCCESS(f'   Staff access: Yes'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ An error occurred during super admin creation: {e}')) 