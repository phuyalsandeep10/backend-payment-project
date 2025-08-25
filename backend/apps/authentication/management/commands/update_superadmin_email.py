"""
Django Management Command: Update Super Admin Email
Updates the super admin email and upgrades the target user
"""
from django.core.management.base import BaseCommand
from apps.authentication.models import User
from apps.permissions.models import Role
import os

class Command(BaseCommand):
    help = 'Updates super admin email and upgrades target user to super admin.'

    def add_arguments(self, parser):
        parser.add_argument('--old-email', type=str, help='Current super admin email')
        parser.add_argument('--new-email', type=str, help='New super admin email')
        parser.add_argument('--password', type=str, help='Password for the new super admin')

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('--- Updating Super Admin Email ---'))

        # Get emails from arguments or environment variables
        old_email = options.get('old_email') or 'super@innovate.com'
        new_email = options.get('new_email') or os.getenv('ADMIN_EMAIL')
        new_password = options.get('password') or os.getenv('ADMIN_PASS')

        if not new_email:
            self.stdout.write(self.style.ERROR('New email is required. Provide --new-email argument or set ADMIN_EMAIL in .env'))
            return

        try:
            # Get the current super admin
            current_superadmin = User.objects.filter(is_superuser=True, email=old_email).first()
            
            if not current_superadmin:
                self.stdout.write(self.style.WARNING(f'No super admin found with email: {old_email}'))
                self.stdout.write(self.style.SUCCESS('Proceeding to upgrade target user to super admin...'))
            else:
                self.stdout.write(self.style.SUCCESS(f'Found current super admin: {old_email}'))
                # Update the current super admin email
                current_superadmin.email = new_email
                if new_password:
                    current_superadmin.set_password(new_password)
                current_superadmin.save()
                self.stdout.write(self.style.SUCCESS(f'✅ Updated super admin email to: {new_email}'))
                return

            # If no current super admin found, upgrade the target user
            target_user = User.objects.filter(email=new_email).first()
            
            if not target_user:
                self.stdout.write(self.style.ERROR(f'❌ User with email {new_email} does not exist.'))
                return

            # Get or create Super Admin role (use the first one if multiple exist)
            super_admin_role = Role.objects.filter(name='Super Admin').first()
            if not super_admin_role:
                super_admin_role, created = Role.objects.get_or_create(name='Super Admin')
                if created:
                    self.stdout.write(self.style.SUCCESS('Created "Super Admin" role.'))

            # Upgrade target user to super admin
            target_user.is_superuser = True
            target_user.is_staff = True
            target_user.role = super_admin_role
            
            # Update password if provided
            if new_password:
                target_user.set_password(new_password)
                self.stdout.write(self.style.SUCCESS('Password updated.'))
            
            target_user.save()
            
            self.stdout.write(self.style.SUCCESS(f'✅ Successfully upgraded user to super admin: {new_email}'))
            self.stdout.write(self.style.SUCCESS(f'   Username: {target_user.username}'))
            self.stdout.write(self.style.SUCCESS(f'   Role: Super Admin'))
            self.stdout.write(self.style.SUCCESS(f'   Staff access: Yes'))
            self.stdout.write(self.style.SUCCESS(f'   Superuser: Yes'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ An error occurred: {e}')) 