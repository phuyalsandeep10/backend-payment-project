from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import transaction
from authentication.models import User
from permissions.models import Role, Permission
from organization.models import Organization

class Command(BaseCommand):
    help = 'Fix deployment permission issues and ensure all users have proper access'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force recreation of permissions even if they exist'
        )
        parser.add_argument(
            '--organization',
            type=str,
            help='Specific organization to fix (default: all)'
        )

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🔧 Starting deployment permission fix..."))
        
        # Step 1: Ensure organizations exist
        self.stdout.write(self.style.HTTP_INFO("📋 Step 1: Ensuring organizations exist..."))
        organizations = Organization.objects.all()
        if not organizations.exists():
            self.stdout.write(self.style.WARNING("⚠️  No organizations found. Creating default organization..."))
            org = Organization.objects.create(
                name="Innovate Inc.",
                description="A leading innovation company"
            )
            self.stdout.write(self.style.SUCCESS(f"✅ Created organization: {org.name}"))
        else:
            self.stdout.write(self.style.SUCCESS(f"✅ Found {organizations.count()} organization(s)"))
        
        # Step 2: Create all permissions
        self.stdout.write(self.style.HTTP_INFO("🔐 Step 2: Creating all permissions..."))
        try:
            call_command('create_all_permissions')
            self.stdout.write(self.style.SUCCESS("✅ All permissions created"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error creating permissions: {e}"))
            return
        
        # Step 3: Create deal permissions
        self.stdout.write(self.style.HTTP_INFO("🔐 Step 3: Creating deal permissions..."))
        try:
            call_command('create_deal_permissions')
            self.stdout.write(self.style.SUCCESS("✅ Deal permissions created"))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"⚠️  Warning creating deal permissions: {e}"))
        
        # Step 4: Setup permissions for all organizations
        target_orgs = organizations
        if options['organization']:
            target_orgs = organizations.filter(name=options['organization'])
            if not target_orgs.exists():
                self.stdout.write(self.style.ERROR(f"❌ Organization '{options['organization']}' not found!"))
                return
        
        for org in target_orgs:
            self.stdout.write(self.style.HTTP_INFO(f"🏢 Step 4: Setting up permissions for {org.name}..."))
            
            # Create roles if they don't exist
            role_names = ["Super Admin", "Organization Admin", "Salesperson", "Verifier"]
            for role_name in role_names:
                role, created = Role.objects.get_or_create(
                    name=role_name,
                    organization=org if role_name != "Super Admin" else None
                )
                if created:
                    self.stdout.write(f"  ✅ Created role: {role_name}")
            
            # Assign permissions to roles
            try:
                call_command('assign_role_permissions', organization=org.name)
                self.stdout.write(self.style.SUCCESS(f"✅ Permissions assigned for {org.name}"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Error assigning permissions for {org.name}: {e}"))
        
        # Step 5: Fix specific user issues
        self.stdout.write(self.style.HTTP_INFO("👤 Step 5: Fixing user permission issues..."))
        
        # Fix sales@innovate.com user
        try:
            sales_user = User.objects.get(email='sales@innovate.com')
            if not sales_user.role:
                # Find the Salesperson role for the user's organization
                sales_role = Role.objects.filter(
                    name='Salesperson',
                    organization=sales_user.organization
                ).first()
                if sales_role:
                    sales_user.role = sales_role
                    sales_user.save()
                    self.stdout.write(self.style.SUCCESS("✅ Fixed sales@innovate.com role assignment"))
                else:
                    self.stdout.write(self.style.ERROR("❌ Could not find Salesperson role for sales@innovate.com"))
            else:
                self.stdout.write(self.style.SUCCESS("✅ sales@innovate.com already has role assigned"))
        except User.DoesNotExist:
            self.stdout.write(self.style.WARNING("⚠️  sales@innovate.com user not found"))
        
        # Fix verifier@innovate.com user
        try:
            verifier_user = User.objects.get(email='verifier@innovate.com')
            if not verifier_user.role:
                verifier_role = Role.objects.filter(
                    name='Verifier',
                    organization=verifier_user.organization
                ).first()
                if verifier_role:
                    verifier_user.role = verifier_role
                    verifier_user.save()
                    self.stdout.write(self.style.SUCCESS("✅ Fixed verifier@innovate.com role assignment"))
                else:
                    self.stdout.write(self.style.ERROR("❌ Could not find Verifier role for verifier@innovate.com"))
            else:
                self.stdout.write(self.style.SUCCESS("✅ verifier@innovate.com already has role assigned"))
        except User.DoesNotExist:
            self.stdout.write(self.style.WARNING("⚠️  verifier@innovate.com user not found"))
        
        # Step 6: Verify critical permissions
        self.stdout.write(self.style.HTTP_INFO("🔍 Step 6: Verifying critical permissions..."))
        
        critical_permissions = [
            'view_all_deals', 'create_deal', 'edit_deal', 'delete_deal',
            'view_all_clients', 'create_new_client', 'edit_client_details',
            'view_payment_verification_dashboard', 'verify_deal_payment'
        ]
        
        missing_permissions = []
        for perm_codename in critical_permissions:
            if not Permission.objects.filter(codename=perm_codename).exists():
                missing_permissions.append(perm_codename)
        
        if missing_permissions:
            self.stdout.write(self.style.ERROR(f"❌ Missing critical permissions: {missing_permissions}"))
        else:
            self.stdout.write(self.style.SUCCESS("✅ All critical permissions present"))
        
        # Step 7: Final verification
        self.stdout.write(self.style.HTTP_INFO("🎯 Step 7: Final verification..."))
        
        try:
            sales_user = User.objects.get(email='sales@innovate.com')
            if sales_user.role and sales_user.role.name == 'Salesperson':
                permissions = list(sales_user.role.permissions.values_list('codename', flat=True))
                required_perms = ['view_all_deals', 'create_deal']
                has_required = all(perm in permissions for perm in required_perms)
                
                if has_required:
                    self.stdout.write(self.style.SUCCESS("✅ sales@innovate.com has all required permissions for dashboard access"))
                else:
                    self.stdout.write(self.style.ERROR("❌ sales@innovate.com missing required permissions"))
            else:
                self.stdout.write(self.style.ERROR("❌ sales@innovate.com doesn't have Salesperson role"))
        except User.DoesNotExist:
            self.stdout.write(self.style.WARNING("⚠️  sales@innovate.com user not found"))
        
        self.stdout.write(self.style.SUCCESS("🎉 Deployment permission fix completed!"))
        self.stdout.write(self.style.HTTP_INFO("💡 You can now test the API endpoints with proper permissions.")) 