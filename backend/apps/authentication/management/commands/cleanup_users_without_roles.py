from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction

User = get_user_model()

class Command(BaseCommand):
    help = 'Remove users without roles from the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force deletion without confirmation',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        force = options['force']
        
        self.stdout.write("=== Cleanup Users Without Roles ===")
        
        # Find users without roles
        users_without_roles = User.objects.filter(role__isnull=True)
        total_users_without_roles = users_without_roles.count()
        
        if total_users_without_roles == 0:
            self.stdout.write(self.style.SUCCESS("✅ No users without roles found. Database is clean!"))
            return
        
        self.stdout.write(f"Found {total_users_without_roles} users without roles:")
        
        # Show users that would be deleted
        for user in users_without_roles:
            org_name = user.organization.name if user.organization else "No Organization"
            self.stdout.write(f"  - {user.email} ({user.first_name} {user.last_name}) - Org: {org_name}")
        
        if dry_run:
            self.stdout.write(self.style.WARNING(f"\n🔍 DRY RUN: Would delete {total_users_without_roles} users without roles"))
            self.stdout.write("Run without --dry-run to actually perform the deletion")
            return
        
        # Confirm deletion unless forced
        if not force:
            self.stdout.write(f"\n⚠️  WARNING: This will permanently delete {total_users_without_roles} users!")
            self.stdout.write("These users appear to be incomplete (missing roles) and may cause issues.")
            
            confirm = input("\nAre you sure you want to continue? Type 'YES' to confirm: ")
            if confirm != 'YES':
                self.stdout.write(self.style.ERROR("❌ Operation cancelled by user"))
                return
        
        # Perform deletion
        try:
            with transaction.atomic():
                # Delete users without roles
                deleted_count = users_without_roles.delete()[0]
                
                self.stdout.write(self.style.SUCCESS(f"\n✅ Successfully deleted {deleted_count} users without roles"))
                
                # Show remaining users
                remaining_users = User.objects.count()
                self.stdout.write(f"Remaining users in database: {remaining_users}")
                
                # Show remaining users with roles
                users_with_roles = User.objects.filter(role__isnull=False).count()
                self.stdout.write(f"Users with roles: {users_with_roles}")
                
                # Show remaining users without roles (should be 0)
                remaining_without_roles = User.objects.filter(role__isnull=True).count()
                self.stdout.write(f"Users without roles: {remaining_without_roles}")
                
                if remaining_without_roles == 0:
                    self.stdout.write(self.style.SUCCESS("✅ All remaining users now have proper role assignments!"))
                else:
                    self.stdout.write(self.style.WARNING(f"⚠️  {remaining_without_roles} users still don't have roles"))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error during deletion: {e}"))
            self.stdout.write("No users were deleted due to the error")
            return
        
        self.stdout.write("\n=== Cleanup Complete ===")
