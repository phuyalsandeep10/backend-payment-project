import os
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from dotenv import load_dotenv
load_dotenv()

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates a single super-admin user from environment variables. Fails if one already exists.'

    def handle(self, *args, **options):
        # Enforce a single super-admin policy
        if User.objects.filter(role=User.Role.SUPER_ADMIN).exists():
            self.stdout.write(self.style.WARNING('A super-admin user already exists. Skipping creation.'))
            return

        username = os.environ.get('ADMIN_USER')
        email = os.environ.get('ADMIN_EMAIL')
        password = os.environ.get('ADMIN_PASS')

        if not all([username, email, password]):
            self.stdout.write(self.style.ERROR('Please set ADMIN_USER, ADMIN_EMAIL, and ADMIN_PASS environment variables.'))
            return

        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f'User "{username}" already exists. Skipping.'))
            return

        User.objects.create_superuser(username=username, email=email, password=password, role=User.Role.SUPER_ADMIN)
        self.stdout.write(self.style.SUCCESS(f'Successfully created super-admin user "{username}"'))
        self.stdout.write(self.style.SUCCESS(f'Password: {password}'))
