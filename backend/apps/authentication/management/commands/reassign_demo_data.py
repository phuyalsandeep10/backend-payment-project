from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.contrib.auth import get_user_model
from apps.organization.models import Organization
from apps.permissions.models import Role

User = get_user_model()

class Command(BaseCommand):
    """
    Reassigns all seeded data from a demo organization to a specific user,
    making them the Organization Admin of that data set.
    """
    help = "Reassign all demo data from 'Innovate Inc.' to a specific user's email."

    def add_arguments(self, parser):
        parser.add_argument('email', type=str, help="The email of the user who will own the demo data.")
        parser.add_argument(
            '--org_name',
            type=str,
            default="Innovate Inc.",
            help="The name of the organization whose data will be reassigned."
        )

    @transaction.atomic
    def handle(self, *args, **options):
        email = options['email']
        org_name = options['org_name']

        self.stdout.write(self.style.NOTICE(f"Attempting to make '{email}' the admin of '{org_name}'..."))

        try:
            target_user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise CommandError(f"User with email '{email}' not found. Please ensure the user exists.")

        try:
            source_org = Organization.objects.get(name=org_name)
        except Organization.DoesNotExist:
            raise CommandError(f"Organization '{org_name}' not found. Has the demo data been seeded?")

        try:
            org_admin_role = Role.objects.get(name="Organization Admin", organization=source_org)
        except Role.DoesNotExist:
            raise CommandError(f"Role 'Organization Admin' for org '{org_name}' not found.")

        # --- Reassignment ---
        # 1. Update the target user's profile
        target_user.organization = source_org
        target_user.role = org_admin_role
        target_user.is_staff = True  # Useful for admin panel access
        target_user.save()
        self.stdout.write(self.style.SUCCESS(f"✅ User '{email}' is now an Org Admin for '{org_name}'."))

        # 2. Find the old demo org admin to replace
        try:
            old_admin = User.objects.get(email='orgadmin@innovate.com', organization=source_org)
            
            # 3. Reassign any objects created by the old admin to the new admin
            # This is a simple reassignment; more complex scenarios might need more specific logic.
            # Example for one model:
            from apps.deals.models import Deal
            deals_reassigned = Deal.objects.filter(created_by=old_admin).update(created_by=target_user)
            self.stdout.write(f"  - Reassigned {deals_reassigned} Deals.")

            # You can add more models here as needed, e.g., for clients, teams, etc.
            # from apps.clients.models import Client
            # clients_reassigned = Client.objects.filter(created_by=old_admin).update(created_by=target_user)
            # self.stdout.write(f"  - Reassigned {clients_reassigned} Clients.")

            # 4. Deactivate the old demo admin user
            old_admin.is_active = False
            old_admin.save()
            self.stdout.write(self.style.WARNING(f"  - Deactivated the old demo admin 'orgadmin@innovate.com'."))

        except User.DoesNotExist:
            self.stdout.write(self.style.WARNING("  - Old demo admin 'orgadmin@innovate.com' not found, skipping reassignment."))


        self.stdout.write(self.style.SUCCESS(f"\nAll done. '{email}' now owns and can see all data for '{org_name}'. Login to see the changes.")) 