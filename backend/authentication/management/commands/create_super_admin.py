import os
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from dotenv import load_dotenv
from django.conf import settings
from authentication.models import User
from permissions.models import Role as OrgRole
load_dotenv()

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates a super admin user if one does not exist.'

    def handle(self, *args, **options):
        # Ensure the Super Admin role exists. It's not tied to any organization.
        super_admin_role, created = OrgRole.objects.get_or_create(
            name='Super Admin', 
            organization=None
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Successfully created "Super Admin" role.'))

        # Check if a user with this role already exists
        if User.objects.filter(org_role=super_admin_role).exists():
            self.stdout.write(self.style.WARNING('A Super Admin user already exists.'))
            return

        # Get credentials from settings
        username = settings.ADMIN_USER
        email = settings.ADMIN_EMAIL
        password = settings.ADMIN_PASS

        if not all([username, email, password]):
            self.stderr.write(self.style.ERROR(
                'Please set ADMIN_USER, ADMIN_EMAIL, and ADMIN_PASS in your .env file.'
            ))
            return

        # Create the super admin user
        user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password
        )
        
        # Assign the role and set is_staff for admin panel access
        user.org_role = super_admin_role
        user.is_staff = True
        user.save()

        self.stdout.write(self.style.SUCCESS(f'Successfully created Super Admin user: {username}'))
