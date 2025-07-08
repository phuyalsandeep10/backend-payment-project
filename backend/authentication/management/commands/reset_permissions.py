from django.core.management.base import BaseCommand
from django.db import transaction
from django.contrib.auth.models import Permission
from permissions.models import Role
from organization.models import Organization

class Command(BaseCommand):
    help = 'Completely reset permissions and roles (NUCLEAR OPTION - use with caution)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force reset without confirmation'
        )

    def handle(self, *args, **options):
        if not options['force']:
            self.stdout.write(self.style.ERROR("⚠️  NUCLEAR OPTION: This will delete ALL roles and their permission assignments!"))
            self.stdout.write(self.style.ERROR("⚠️  Use --force to proceed"))
            return
        
        self.stdout.write(self.style.HTTP_INFO("🚨 NUCLEAR OPTION: Resetting all permissions and roles..."))
        
        with transaction.atomic():
            # Step 1: Delete all roles (this will cascade to role-permission assignments)
            role_count = Role.objects.count()
            self.stdout.write(f"🗑️  Deleting {role_count} roles...")
            Role.objects.all().delete()
            self.stdout.write(f"✅ Deleted {role_count} roles")
            
            # Step 2: Delete all custom permissions (keep Django's built-in ones)
            custom_permission_count = Permission.objects.exclude(
                content_type__app_label__in=['admin', 'auth', 'contenttypes', 'sessions']
            ).count()
            self.stdout.write(f"🗑️  Deleting {custom_permission_count} custom permissions...")
            Permission.objects.exclude(
                content_type__app_label__in=['admin', 'auth', 'contenttypes', 'sessions']
            ).delete()
            self.stdout.write(f"✅ Deleted {custom_permission_count} custom permissions")
            
            # Step 3: Show remaining permissions
            remaining_permissions = Permission.objects.count()
            self.stdout.write(f"📊 Remaining Django built-in permissions: {remaining_permissions}")
            
            # Step 4: Create fresh permissions
            self.stdout.write("📝 Creating fresh permissions...")
            from django.core.management import call_command
            call_command('create_all_permissions')
            
            # Step 5: Create fresh roles
            self.stdout.write("📝 Creating fresh roles...")
            for organization in Organization.objects.all():
                self.stdout.write(f"  Creating roles for organization: {organization.name}")
                for role_name in ["Super Admin", "Organization Admin", "Salesperson", "Verifier"]:
                    role, created = Role.objects.get_or_create(
                        name=role_name,
                        organization=organization
                    )
                    if created:
                        self.stdout.write(f"    ✅ Created role: {role_name}")
                    else:
                        self.stdout.write(f"    ℹ️  Role already exists: {role_name}")
            
            # Step 6: Assign permissions to roles
            self.stdout.write("📝 Assigning permissions to roles...")
            call_command('assign_role_permissions')
        
        self.stdout.write(self.style.SUCCESS("🎉 Nuclear reset completed successfully!"))
        self.stdout.write(self.style.HTTP_INFO("💡 Your database now has fresh permissions and roles")) 