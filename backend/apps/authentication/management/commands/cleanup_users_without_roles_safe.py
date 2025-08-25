from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction, IntegrityError

User = get_user_model()

class Command(BaseCommand):
    help = 'Safely remove users without roles from the database, handling errors gracefully'

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
        
        self.stdout.write("=== Safe Cleanup Users Without Roles ===")
        
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
        
        # Perform deletion one by one to handle errors gracefully
        deleted_count = 0
        failed_count = 0
        failed_users = []
        
        self.stdout.write(f"\n🔄 Starting safe deletion of {total_users_without_roles} users...")
        
        for user in users_without_roles:
            try:
                self.stdout.write(f"  Deleting user: {user.email}...")
                
                # Try to delete the user
                user.delete()
                deleted_count += 1
                self.stdout.write(f"    ✅ Successfully deleted: {user.email}")
                
            except Exception as e:
                failed_count += 1
                failed_users.append((user.email, str(e)))
                self.stdout.write(f"    ❌ Failed to delete {user.email}: {e}")
                
                # Continue with next user instead of stopping
                continue
        
        # Summary
        self.stdout.write(f"\n=== Cleanup Summary ===")
        self.stdout.write(f"Total users processed: {total_users_without_roles}")
        self.stdout.write(f"Successfully deleted: {deleted_count}")
        self.stdout.write(f"Failed to delete: {failed_count}")
        
        if deleted_count > 0:
            self.stdout.write(self.style.SUCCESS(f"✅ Successfully cleaned up {deleted_count} users without roles"))
        
        if failed_count > 0:
            self.stdout.write(self.style.WARNING(f"⚠️  {failed_count} users could not be deleted:"))
            for email, error in failed_users:
                self.stdout.write(f"    - {email}: {error}")
        
        # Check final state
        remaining_users = User.objects.count()
        remaining_with_roles = User.objects.filter(role__isnull=False).count()
        remaining_without_roles = User.objects.filter(role__isnull=True).count()
        
        self.stdout.write(f"\nFinal Database State:")
        self.stdout.write(f"  Total Users: {remaining_users}")
        self.stdout.write(f"  Users with Roles: {remaining_with_roles}")
        self.stdout.write(f"  Users without Roles: {remaining_without_roles}")
        
        if remaining_without_roles == 0:
            self.stdout.write(self.style.SUCCESS("✅ All remaining users now have proper role assignments!"))
        else:
            self.stdout.write(self.style.WARNING(f"⚠️  {remaining_without_roles} users still don't have roles"))
        
        self.stdout.write("\n=== Cleanup Complete ===")
