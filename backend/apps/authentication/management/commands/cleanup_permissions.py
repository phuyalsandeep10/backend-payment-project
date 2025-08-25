from django.core.management.base import BaseCommand
from django.db import transaction
from django.contrib.auth.models import Permission
from apps.permissions.models import Role
from apps.organization.models import Organization

class Command(BaseCommand):
    help = 'Clean up orphaned permission assignments and ensure all permissions exist'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force cleanup without confirmation'
        )

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("🧹 Starting permission cleanup..."))
        
        # Step 1: Check for orphaned permission assignments
        self.stdout.write("📋 Step 1: Checking for orphaned permission assignments...")
        
        # Get all role-permission assignments
        orphaned_count = 0
        for role in Role.objects.all():
            # Get all permission IDs that this role has
            role_permission_ids = list(role.permissions.values_list('id', flat=True))
            
            # Check which permissions actually exist
            existing_permission_ids = list(Permission.objects.filter(id__in=role_permission_ids).values_list('id', flat=True))
            
            # Find orphaned permissions
            orphaned_ids = set(role_permission_ids) - set(existing_permission_ids)
            
            if orphaned_ids:
                self.stdout.write(f"  ❌ Role '{role.name}' has {len(orphaned_ids)} orphaned permissions: {orphaned_ids}")
                orphaned_count += len(orphaned_ids)
                
                # Remove orphaned permissions
                role.permissions.remove(*orphaned_ids)
                self.stdout.write(f"  ✅ Removed orphaned permissions from role '{role.name}'")
            else:
                self.stdout.write(f"  ✅ Role '{role.name}' has no orphaned permissions")
        
        self.stdout.write(self.style.SUCCESS(f"📊 Total orphaned permissions removed: {orphaned_count}"))
        
        # Step 2: Verify all required permissions exist
        self.stdout.write("📋 Step 2: Verifying all required permissions exist...")
        
        # Define all required permissions
        required_permissions = [
            # Deal permissions
            'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 'delete_deal',
            'log_deal_activity', 'verify_deal_payment', 'verify_payments', 'manage_invoices',
            'access_verification_queue', 'manage_refunds',
            
            # Client permissions
            'view_all_clients', 'view_own_clients', 'create_new_client', 'edit_client_details', 'remove_client',
            
            # Team permissions
            'view_all_teams', 'view_own_teams', 'create_new_team', 'edit_team_details', 'remove_team',
            
            # Commission permissions
            'view_all_commissions', 'create_commission', 'edit_commission',
            
            # Project permissions
            'view_all_projects', 'view_own_projects', 'create_project', 'edit_project', 'delete_project',
            
            # Payment invoice permissions
            'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
            
            # Payment approval permissions
            'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
            
            # Verifier dashboard permissions
            'view_payment_verification_dashboard', 'view_payment_analytics', 'view_audit_logs',
            
            # Standard Django permissions (these should always exist)
            'add_user', 'change_user', 'delete_user', 'view_user',
            'add_client', 'change_client', 'delete_client', 'view_client',
            'add_deal', 'change_deal', 'delete_deal', 'view_deal',
            'add_project', 'change_project', 'delete_project', 'view_project',
            'add_team', 'change_team', 'delete_team', 'view_team',
            'add_commission', 'change_commission', 'delete_commission', 'view_commission',
            'add_notification', 'change_notification', 'delete_notification', 'view_notification',
            'add_auditlogs', 'change_auditlogs', 'delete_auditlogs', 'view_auditlogs',
        ]
        
        missing_permissions = []
        for codename in required_permissions:
            if not Permission.objects.filter(codename=codename).exists():
                missing_permissions.append(codename)
                self.stdout.write(f"  ❌ Missing permission: {codename}")
        
        if missing_permissions:
            self.stdout.write(self.style.WARNING(f"⚠️  Found {len(missing_permissions)} missing permissions"))
            self.stdout.write(self.style.WARNING("💡 Run 'python manage.py create_all_permissions' to create missing permissions"))
        else:
            self.stdout.write(self.style.SUCCESS("✅ All required permissions exist"))
        
        # Step 3: Show current permission statistics
        self.stdout.write("📋 Step 3: Current permission statistics...")
        
        total_permissions = Permission.objects.count()
        total_roles = Role.objects.count()
        
        self.stdout.write(f"  📊 Total permissions in database: {total_permissions}")
        self.stdout.write(f"  📊 Total roles in database: {total_roles}")
        
        for role in Role.objects.all():
            permission_count = role.permissions.count()
            self.stdout.write(f"  📊 Role '{role.name}': {permission_count} permissions")
        
        self.stdout.write(self.style.SUCCESS("🎉 Permission cleanup completed!"))
        
        if missing_permissions:
            self.stdout.write(self.style.WARNING("⚠️  Please run 'python manage.py create_all_permissions' to create missing permissions"))
            self.stdout.write(self.style.WARNING("⚠️  Then run 'python manage.py setup_permissions' to assign permissions to roles")) 