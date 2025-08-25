from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from apps.authentication.models import User
from apps.permissions.models import Role
from apps.organization.models import Organization


class Command(BaseCommand):
    help = "Fix permissions on deployment environment to ensure all roles have complete permission sets"

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force recreate all permissions even if they exist',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🔧 Fixing Deployment Permissions"))
        self.stdout.write("=" * 50)
        
        try:
            # Get the organization
            organization = Organization.objects.get(name="Innovate Inc.")
            self.stdout.write(f"✅ Found organization: {organization.name}")
            
            # Create missing permissions
            self.create_missing_permissions()
            
            # Assign complete permissions to roles
            self.assign_complete_permissions(organization)
            
            # Verify verifier user
            self.verify_verifier_user(organization)
            
            self.stdout.write(self.style.SUCCESS("✅ Deployment permissions fixed successfully!"))
            
        except Organization.DoesNotExist:
            self.stdout.write(self.style.ERROR("❌ Organization 'Innovate Inc.' not found"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))

    def create_missing_permissions(self):
        """Create missing permissions that are needed."""
        self.stdout.write("\n🔧 Creating missing permissions...")
        
        # Define permissions to create with their content types
        permissions_to_create = {
            'add_user': 'authentication.user',
            'change_user': 'authentication.user',
            'delete_user': 'authentication.user',
            'view_user': 'authentication.user',
            'create_deal_payment': 'deals.payment',
            'add_payment': 'deals.payment',
            'view_payment': 'deals.payment',
            'change_payment': 'deals.payment',
            'delete_payment': 'deals.payment',
            'add_dailystreakrecord': 'Sales_dashboard.dailystreakrecord',
            'view_dailystreakrecord': 'Sales_dashboard.dailystreakrecord',
            'change_dailystreakrecord': 'Sales_dashboard.dailystreakrecord',
            'delete_dailystreakrecord': 'Sales_dashboard.dailystreakrecord'
        }
        
        created_count = 0
        
        for codename, content_type_str in permissions_to_create.items():
            try:
                # Check if permission already exists
                existing = Permission.objects.filter(codename=codename).first()
                if existing:
                    self.stdout.write(f"  ✅ {codename} already exists")
                    continue
                
                # Parse content type
                app_label, model_name = content_type_str.split('.')
                content_type = ContentType.objects.get(app_label=app_label, model=model_name)
                
                # Create permission
                permission = Permission.objects.create(
                    codename=codename,
                    name=f"Can {codename.replace('_', ' ')}",
                    content_type=content_type
                )
                self.stdout.write(f"  ✅ Created {codename}")
                created_count += 1
                
            except Exception as e:
                self.stdout.write(self.style.WARNING(f"  ⚠️  Failed to create {codename}: {e}"))
        
        self.stdout.write(f"✅ Created {created_count} new permissions")

    def assign_complete_permissions(self, organization):
        """Assign complete permission sets to all roles."""
        self.stdout.write("\n🔐 Assigning complete permissions to roles...")
        
        # Define complete permission sets for each role
        role_permissions = {
            "Organization Admin": [
                # User management
                'add_user', 'change_user', 'delete_user', 'view_user',
                # Client management
                'add_client', 'change_client', 'delete_client', 'view_client',
                'view_all_clients', 'view_own_clients', 'create_new_client', 'edit_client_details', 'remove_client',
                # Deal management
                'add_deal', 'change_deal', 'delete_deal', 'view_deal',
                'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 'log_deal_activity',
                'verify_deal_payment', 'verify_payments', 'manage_invoices', 'access_verification_queue', 'manage_refunds',
                # Project management
                'add_project', 'change_project', 'delete_project', 'view_project',
                'view_all_projects', 'view_own_projects', 'create_project', 'edit_project', 'delete_project',
                # Team management
                'add_team', 'change_team', 'delete_team', 'view_team',
                'view_all_teams', 'view_own_teams', 'create_new_team', 'edit_team_details', 'remove_team',
                # Commission management
                'add_commission', 'change_commission', 'delete_commission', 'view_commission',
                'view_all_commissions', 'create_commission', 'edit_commission',
                # Payment management
                'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
                'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
                # Notifications
                'add_notification', 'change_notification', 'delete_notification', 'view_notification',
                # Dashboard
                'view_audit_logs', 'view_payment_verification_dashboard', 'view_payment_analytics',
                # Role management
                'can_manage_roles'
            ],
            "Salesperson": [
                # Client permissions
                'view_own_clients', 'create_new_client', 'edit_client_details', 'remove_client',
                # Deal permissions
                'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 'delete_deal', 'log_deal_activity',
                # Project permissions
                'view_all_projects', 'view_own_projects', 'create_project', 'edit_project', 'delete_project',
                # Team permissions
                'view_all_teams', 'view_own_teams', 'create_new_team', 'edit_team_details', 'remove_team',
                # Commission permissions
                'view_commission', 'view_all_commissions', 'create_commission', 'edit_commission',
                # Payment permissions
                'create_deal_payment', 'add_payment', 'view_payment', 'change_payment', 'delete_payment',
                'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
                'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
                # Dashboard permissions
                'add_dailystreakrecord', 'view_dailystreakrecord', 'change_dailystreakrecord', 'delete_dailystreakrecord'
            ],
            "Verifier": [
                # Core verifier permissions
                'view_payment_verification_dashboard', 'view_payment_analytics', 'view_audit_logs',
                'verify_deal_payment', 'verify_payments', 'manage_invoices', 'access_verification_queue', 'manage_refunds',
                # Deal viewing permissions
                'view_all_deals', 'view_own_deals',
                # Client viewing permissions
                'view_all_clients', 'view_own_clients',
                # Payment management
                'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
                'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval'
            ]
        }
        
        for role_name, permission_codenames in role_permissions.items():
            try:
                role = Role.objects.get(name=role_name, organization=organization)
                self.stdout.write(f"\n🔧 Assigning permissions to {role_name}...")
                
                # Clear existing permissions
                role.permissions.clear()
                
                # Get permissions that exist
                permissions_to_add = []
                for codename in permission_codenames:
                    try:
                        # Use filter().first() to handle duplicates
                        perm = Permission.objects.filter(codename=codename).first()
                        if perm:
                            permissions_to_add.append(perm)
                        else:
                            self.stdout.write(self.style.WARNING(f"  ⚠️  Permission '{codename}' not found, skipping"))
                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f"  ⚠️  Error getting permission '{codename}': {e}"))
                
                # Add permissions
                if permissions_to_add:
                    role.permissions.add(*permissions_to_add)
                    self.stdout.write(f"  ✅ Assigned {len(permissions_to_add)} permissions to {role_name}")
                else:
                    self.stdout.write(self.style.ERROR(f"  ❌ No permissions found for {role_name}"))
                    
            except Role.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"  ❌ Role '{role_name}' not found"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  ❌ Error assigning permissions to {role_name}: {e}"))

    def verify_verifier_user(self, organization):
        """Verify that the verifier user has the correct role and permissions."""
        self.stdout.write("\n🔍 Verifying verifier user...")
        
        try:
            verifier_user = User.objects.get(username='verifier')
            verifier_role = Role.objects.get(name='Verifier', organization=organization)
            
            self.stdout.write(f"  - Verifier user: {verifier_user.username}")
            self.stdout.write(f"  - Current role: {verifier_user.role.name if verifier_user.role else 'None'}")
            self.stdout.write(f"  - Organization: {verifier_user.organization.name if verifier_user.organization else 'None'}")
            
            # Ensure verifier user has the correct role
            if verifier_user.role != verifier_role:
                verifier_user.role = verifier_role
                verifier_user.save(update_fields=['role'])
                self.stdout.write("  ✅ Updated verifier user role")
            else:
                self.stdout.write("  ✅ Verifier user has correct role")
            
            # Check permissions
            if verifier_user.role:
                permission_count = verifier_user.role.permissions.count()
                self.stdout.write(f"  - Permissions count: {permission_count}")
                
                # Check key verifier permissions
                key_permissions = [
                    'view_payment_verification_dashboard',
                    'verify_deal_payment',
                    'view_audit_logs',
                    'access_verification_queue'
                ]
                
                for perm_name in key_permissions:
                    has_perm = verifier_user.role.permissions.filter(codename=perm_name).exists()
                    status = "✅" if has_perm else "❌"
                    self.stdout.write(f"    {status} {perm_name}")
                
                if permission_count >= 20:
                    self.stdout.write("  ✅ Verifier has sufficient permissions")
                else:
                    self.stdout.write(self.style.WARNING(f"  ⚠️  Verifier has only {permission_count} permissions"))
            else:
                self.stdout.write(self.style.ERROR("  ❌ Verifier user has no role"))
                
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR("  ❌ Verifier user not found"))
        except Role.DoesNotExist:
            self.stdout.write(self.style.ERROR("  ❌ Verifier role not found"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"  ❌ Error verifying verifier user: {e}")) 