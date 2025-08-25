"""
Django Management Command: Upgrade User to Super Admin
Upgrades an existing user to super admin status
"""
from django.core.management.base import BaseCommand
from apps.authentication.models import User
from apps.permissions.models import Role
import os

class Command(BaseCommand):
    help = 'Upgrades an existing user to super admin status.'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, help='User email to upgrade')
        parser.add_argument('--password', type=str, help='New password for the user (optional)')

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('--- Upgrading User to Super Admin ---'))

        # Get email from arguments or environment variables
        admin_email = options.get('email') or os.getenv('ADMIN_EMAIL')
        new_password = options.get('password') or os.getenv('ADMIN_PASS')

        if not admin_email:
            self.stdout.write(self.style.ERROR('Email is required. Provide --email argument or set ADMIN_EMAIL in .env'))
            return

        try:
            # Get the user
            user = User.objects.get(email=admin_email)
            
            # Get or create Super Admin role
            super_admin_role, created = Role.objects.get_or_create(name='Super Admin')
            if created:
                self.stdout.write(self.style.SUCCESS('Created "Super Admin" role.'))

            # Update user to super admin
            user.is_superuser = True
            user.is_staff = True
            user.role = super_admin_role
            
            # Update password if provided
            if new_password:
                user.set_password(new_password)
                self.stdout.write(self.style.SUCCESS('Password updated.'))
            
            user.save()
            
            self.stdout.write(self.style.SUCCESS(f'✅ Successfully upgraded user to super admin: {admin_email}'))
            self.stdout.write(self.style.SUCCESS(f'   Username: {user.username}'))
            self.stdout.write(self.style.SUCCESS(f'   Role: Super Admin'))
            self.stdout.write(self.style.SUCCESS(f'   Staff access: Yes'))
            self.stdout.write(self.style.SUCCESS(f'   Superuser: Yes'))

        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'❌ User with email {admin_email} does not exist.'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ An error occurred: {e}')) 