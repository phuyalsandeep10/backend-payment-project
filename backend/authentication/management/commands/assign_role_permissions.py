from django.core.management.base import BaseCommand
from django.db import transaction
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from permissions.models import Role
from organization.models import Organization

class Command(BaseCommand):
    help = 'Assigns proper permissions to roles based on their responsibilities'

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

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🔐 Starting role permission assignment..."))

        # Get organizations to process
        if options['organization']:
            organizations = Organization.objects.filter(name=options['organization'])
            if not organizations.exists():
                self.stdout.write(self.style.ERROR(f"❌ Organization '{options['organization']}' not found!"))
                return
        else:
            organizations = Organization.objects.all()

        # Get roles to process
        role_names = ["Super Admin", "Organization Admin", "Salesperson", "Verifier"]
        if options['role']:
            if options['role'] not in role_names:
                self.stdout.write(self.style.ERROR(f"❌ Role '{options['role']}' not found!"))
                return
            role_names = [options['role']]

        for organization in organizations:
            self.stdout.write(self.style.HTTP_INFO(f"--- Processing Organization: {organization.name} ---"))
            
            for role_name in role_names:
                self.assign_permissions_to_role(organization, role_name)

        self.stdout.write(self.style.SUCCESS("✅ Role permission assignment completed!"))

    def assign_permissions_to_role(self, organization, role_name):
        """Assign permissions to a specific role in an organization."""
        try:
            # Get or create the role
            role, created = Role.objects.get_or_create(
                name=role_name,
                organization=organization
            )
            
            if created:
                self.stdout.write(f"  - Created role: {role_name}")
            else:
                self.stdout.write(f"  - Found existing role: {role_name}")

            # Get permissions for this role
            permissions = self.get_permissions_for_role(role_name)
            
            if not permissions:
                self.stdout.write(self.style.WARNING(f"  - No permissions found for role: {role_name}"))
                return

            # Clear existing permissions and assign new ones
            role.permissions.clear()
            role.permissions.add(*permissions)
            
            self.stdout.write(self.style.SUCCESS(f"  ✅ Assigned {len(permissions)} permissions to {role_name}"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"  ❌ Error assigning permissions to {role_name}: {e}"))

    def get_permissions_for_role(self, role_name):
        """Get the list of permissions for a specific role."""
        if role_name == "Super Admin":
            # Super Admin gets all permissions
            return list(Permission.objects.all())
        
        elif role_name == "Organization Admin":
            # Organization Admin gets most permissions except super admin specific ones
            return self.get_org_admin_permissions()
        
        elif role_name == "Salesperson":
            # Salesperson gets sales-related permissions
            return self.get_salesperson_permissions()
        
        elif role_name == "Verifier":
            # Verifier gets verification-related permissions
            return self.get_verifier_permissions()
        
        return []

    def get_org_admin_permissions(self):
        """Get permissions for Organization Admin role."""
        permissions = []
        
        # Get content types
        try:
            content_types = {
                'user': ContentType.objects.get_for_model('authentication.User'),
                'client': ContentType.objects.get_for_model('clients.Client'),
                'deal': ContentType.objects.get_for_model('deals.Deal'),
                'project': ContentType.objects.get_for_model('project.Project'),
                'team': ContentType.objects.get_for_model('team.Team'),
                'commission': ContentType.objects.get_for_model('commission.Commission'),
                'notification': ContentType.objects.get_for_model('notifications.Notification'),
                'audit_log': ContentType.objects.get_for_model('Verifier_dashboard.AuditLogs'),
            }
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"  - Warning: Could not get all content types: {e}"))
            content_types = {}
        
        # User management permissions
        user_permissions = [
            'add_user', 'change_user', 'delete_user', 'view_user',
        ]
        
        # Client management permissions
        client_permissions = [
            'add_client', 'change_client', 'delete_client', 'view_client',
            'view_all_clients', 'view_own_clients', 'create_new_client', 
            'edit_client_details', 'remove_client'
        ]
        
        # Deal management permissions
        deal_permissions = [
            'add_deal', 'change_deal', 'delete_deal', 'view_deal',
            'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 
            'delete_deal', 'log_deal_activity', 'verify_deal_payment', 
            'verify_payments', 'manage_invoices', 'access_verification_queue',
            'manage_refunds'
        ]
        
        # Project management permissions
        project_permissions = [
            'add_project', 'change_project', 'delete_project', 'view_project',
            'view_all_projects', 'view_own_projects', 'create_project', 
            'edit_project', 'delete_project'
        ]
        
        # Team management permissions
        team_permissions = [
            'add_team', 'change_team', 'delete_team', 'view_team',
            'view_all_teams', 'view_own_teams', 'create_new_team', 
            'edit_team_details', 'remove_team'
        ]
        
        # Commission permissions
        commission_permissions = [
            'add_commission', 'change_commission', 'delete_commission', 'view_commission',
            'view_all_commissions', 'create_commission', 'edit_commission'
        ]
        
        # Payment invoice permissions
        payment_invoice_permissions = [
            'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 
            'delete_paymentinvoice'
        ]
        
        # Payment approval permissions
        payment_approval_permissions = [
            'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 
            'delete_paymentapproval'
        ]
        
        # Notification permissions
        notification_permissions = [
            'add_notification', 'change_notification', 'delete_notification', 'view_notification'
        ]
        
        # Audit log permissions
        audit_log_permissions = [
            'view_audit_logs', 'view_payment_verification_dashboard', 'view_payment_analytics'
        ]
        
        # Combine all permissions
        all_permission_codenames = (
            user_permissions + client_permissions + deal_permissions + 
            project_permissions + team_permissions + commission_permissions +
            payment_invoice_permissions + payment_approval_permissions +
            notification_permissions + audit_log_permissions
        )
        
        # Get actual permissions that exist
        permissions = Permission.objects.filter(codename__in=all_permission_codenames)
        
        return list(permissions)

    def get_salesperson_permissions(self):
        """Get permissions for Salesperson role."""
        permissions = []
        
        # Client permissions
        client_permissions = [
            'view_all_clients', 'view_own_clients', 'create_new_client', 
            'edit_client_details', 'remove_client'
        ]
        
        # Deal permissions
        deal_permissions = [
            'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 
            'delete_deal', 'log_deal_activity'
        ]
        
        # Project permissions
        project_permissions = [
            'view_all_projects', 'view_own_projects', 'create_project', 
            'edit_project', 'delete_project'
        ]
        
        # Team permissions
        team_permissions = [
            'view_all_teams', 'view_own_teams', 'create_new_team', 
            'edit_team_details', 'remove_team'
        ]
        
        # Commission permissions
        commission_permissions = [
            'view_all_commissions', 'create_commission', 'edit_commission'
        ]
        
        # Combine all permissions
        all_permission_codenames = (
            client_permissions + deal_permissions + project_permissions + 
            team_permissions + commission_permissions
        )
        
        # Get actual permissions that exist
        permissions = Permission.objects.filter(codename__in=all_permission_codenames)
        
        return list(permissions)

    def get_verifier_permissions(self):
        """Get permissions for Verifier role."""
        permissions = []
        
        # Core verifier permissions
        verifier_permissions = [
            'view_payment_verification_dashboard',
            'view_payment_analytics',
            'view_audit_logs',
            'verify_deal_payment',
            'verify_payments',
            'manage_invoices',
            'access_verification_queue',
            'manage_refunds'
        ]
        
        # Deal viewing permissions
        deal_permissions = [
            'view_all_deals', 'view_own_deals'
        ]
        
        # Client viewing permissions
        client_permissions = [
            'view_all_clients', 'view_own_clients'
        ]
        
        # Payment invoice permissions
        payment_invoice_permissions = [
            'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 
            'delete_paymentinvoice'
        ]
        
        # Payment approval permissions
        payment_approval_permissions = [
            'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 
            'delete_paymentapproval'
        ]
        
        # Combine all permissions
        all_permission_codenames = (
            verifier_permissions + deal_permissions + client_permissions +
            payment_invoice_permissions + payment_approval_permissions
        )
        
        # Get actual permissions that exist
        permissions = Permission.objects.filter(codename__in=all_permission_codenames)
        
        return list(permissions) 