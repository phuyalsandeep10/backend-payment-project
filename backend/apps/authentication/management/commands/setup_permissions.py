from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import transaction

class Command(BaseCommand):
    help = 'Setup all permissions and assign them to roles in the correct order'

    def add_arguments(self, parser):
        parser.add_argument(
            '--organization',
            type=str,
            help='Organization name to assign permissions to (default: all organizations)'
        )
        parser.add_argument(
            '--role',
            type=str,
            help='Specific role to assign permissions to (default: all roles)'
        )
        parser.add_argument(
            '--skip-permission-creation',
            action='store_true',
            help='Skip creating permissions (assume they already exist)'
        )

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🚀 Starting comprehensive permission setup..."))
        
        # Step 0: Clean up any orphaned permission assignments
        self.stdout.write(self.style.HTTP_INFO("🧹 Step 0: Cleaning up orphaned permission assignments..."))
        try:
            call_command('cleanup_permissions')
            self.stdout.write(self.style.SUCCESS("✅ Cleanup completed successfully!"))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"⚠️  Warning during cleanup: {e}"))
        
        # Step 1: Create all missing permissions
        if not options['skip_permission_creation']:
            self.stdout.write(self.style.HTTP_INFO("📝 Step 1: Creating all missing permissions..."))
            try:
                call_command('create_all_permissions')
                self.stdout.write(self.style.SUCCESS("✅ Permissions created successfully!"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Error creating permissions: {e}"))
                return
        else:
            self.stdout.write(self.style.WARNING("⚠️  Skipping permission creation..."))
        
        # Step 2: Create deal permissions (for backward compatibility)
        self.stdout.write(self.style.HTTP_INFO("📝 Step 2: Creating deal permissions..."))
        try:
            call_command('create_deal_permissions')
            self.stdout.write(self.style.SUCCESS("✅ Deal permissions created successfully!"))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"⚠️  Warning creating deal permissions: {e}"))
        
        # Step 3: Assign permissions to roles
        self.stdout.write(self.style.HTTP_INFO("📝 Step 3: Assigning permissions to roles..."))
        
        # Build command arguments
        assign_args = []
        if options['organization']:
            assign_args.extend(['--organization', options['organization']])
        if options['role']:
            assign_args.extend(['--role', options['role']])
        
        try:
            call_command('assign_role_permissions', *assign_args)
            self.stdout.write(self.style.SUCCESS("✅ Permissions assigned successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error assigning permissions: {e}"))
            return
        
        self.stdout.write(self.style.SUCCESS("🎉 Permission setup completed successfully!"))
        self.stdout.write(self.style.HTTP_INFO("💡 You can now run your application with proper role-based permissions.")) 