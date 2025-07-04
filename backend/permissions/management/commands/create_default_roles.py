from django.core.management.base import BaseCommand
from django.db import transaction
from permissions.models import Role, Permission


class Command(BaseCommand):
    help = "Creates default roles and permissions for the system."

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🚀 Creating default roles and permissions..."))

        try:
            self.create_default_permissions()
            self.create_default_roles()
            self.stdout.write(self.style.SUCCESS("✅ Default roles and permissions created successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))

    def create_default_permissions(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Default Permissions ---"))
        
        # Comprehensive permissions for all system features
        permissions_data = {
            "User Management": [
                "Create User", "View User", "Edit User", "Delete User", "View All Users",
                "Manage User Roles", "Reset User Password", "Activate/Deactivate User"
            ],
            "Role Management": [
                "Create Role", "View Role", "Edit Role", "Delete Role", "Assign Role",
                "Manage Permissions", "View All Roles"
            ],
            "Organization Management": [
                "Create Organization", "View Organization", "Edit Organization", "Delete Organization",
                "Manage Organization Settings", "View Organization Analytics"
            ],
            "Client Management": [
                "Create Client", "View Own Clients", "View All Clients", "Edit Client Details",
                "Delete Client", "Export Client Data", "Import Client Data"
            ],
            "Deal Management": [
                "Create Deal", "View Own Deals", "View All Deals", "Edit Deal", "Delete Deal",
                "Verify Deal Payment", "Update Deal Status", "Log Deal Activity", "Export Deal Data"
            ],
            "Team Management": [
                "Create Team", "View Own Teams", "View All Teams", "Edit Team", "Delete Team",
                "Assign Team Members", "Manage Team Roles"
            ],
            "Project Management": [
                "Create Project", "View Own Projects", "View All Projects", "Edit Project", 
                "Delete Project", "Assign Project Members", "Manage Project Timeline"
            ],
            "Commission Management": [
                "Create Commission", "View Own Commissions", "View All Commissions", 
                "Edit Commission", "Delete Commission", "Calculate Commission", "Approve Commission"
            ],
            "Sales Dashboard": [
                "View Own Dashboard", "View Team Dashboard", "View Organization Dashboard",
                "Generate Reports", "Export Analytics", "View Sales Metrics"
            ],
            "Verification": [
                "Verify Payments", "Verify Documents", "Approve Deals", "Reject Deals",
                "Audit Transactions", "Generate Verification Reports"
            ],
            "System Administration": [
                "Manage System Settings", "View System Logs", "Backup Data", "Restore Data",
                "Manage Integrations", "System Monitoring"
            ]
        }

        # Create permissions
        created_permissions = 0
        for category, permission_names in permissions_data.items():
            for name in permission_names:
                codename = name.lower().replace(" ", "_").replace("/", "_")
                permission, created = Permission.objects.get_or_create(
                    codename=codename,
                    defaults={'name': name, 'category': category}
                )
                if created:
                    created_permissions += 1

        self.stdout.write(self.style.SUCCESS(f"📋 {created_permissions} new permissions created"))

    def create_default_roles(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Default Role Templates ---"))
        
        # Define default roles with their permissions (system-wide templates)
        default_roles_data = {
            "Organization Admin": [
                # User Management
                "create_user", "view_user", "edit_user", "delete_user", "view_all_users",
                "manage_user_roles", "reset_user_password", "activate_deactivate_user",
                # Role Management
                "create_role", "view_role", "edit_role", "delete_role", "assign_role",
                "manage_permissions", "view_all_roles",
                # Organization Management
                "view_organization", "edit_organization", "manage_organization_settings",
                "view_organization_analytics",
                # All other management permissions
                "view_all_clients", "create_client", "edit_client_details", "delete_client",
                "view_all_deals", "create_deal", "edit_deal", "delete_deal", "update_deal_status",
                "view_all_teams", "create_team", "edit_team", "delete_team",
                "view_all_projects", "create_project", "edit_project", "delete_project",
                "view_all_commissions", "create_commission", "edit_commission", "delete_commission",
                "view_organization_dashboard", "generate_reports", "export_analytics", "view_sales_metrics"
            ],
            "Sales Manager": [
                "view_user", "view_all_users", "create_user", "edit_user",
                "view_all_clients", "create_client", "edit_client_details",
                "view_all_deals", "create_deal", "edit_deal", "update_deal_status",
                "view_all_teams", "create_team", "edit_team", "assign_team_members",
                "view_all_projects", "create_project", "edit_project",
                "view_all_commissions", "create_commission", "edit_commission",
                "view_team_dashboard", "view_organization_dashboard", "generate_reports",
                "verify_payments", "approve_deals", "view_sales_metrics"
            ],
            "Team Head": [
                "view_user", "create_user", "edit_user",
                "view_all_clients", "create_client", "edit_client_details",
                "view_all_deals", "create_deal", "edit_deal", "update_deal_status",
                "view_own_teams", "view_all_teams", "edit_team", "assign_team_members",
                "view_own_projects", "view_all_projects", "create_project", "edit_project",
                "view_own_commissions", "view_all_commissions",
                "view_team_dashboard", "generate_reports", "view_sales_metrics"
            ],
            "Senior Salesperson": [
                "view_user", "view_own_clients", "view_all_clients", "create_client", "edit_client_details",
                "view_own_deals", "view_all_deals", "create_deal", "edit_deal", "update_deal_status",
                "view_own_teams", "view_own_projects", "create_project",
                "view_own_commissions", "view_own_dashboard", "view_team_dashboard",
                "generate_reports", "view_sales_metrics", "log_deal_activity"
            ],
            "Salesperson": [
                "view_user", "view_own_clients", "create_client", "edit_client_details",
                "view_own_deals", "create_deal", "edit_deal", "log_deal_activity",
                "view_own_teams", "view_own_projects", "view_own_commissions",
                "view_own_dashboard", "view_sales_metrics"
            ],
            "Verifier": [
                "view_user", "view_all_clients", "view_all_deals", "verify_payments",
                "verify_documents", "approve_deals", "reject_deals", "audit_transactions",
                "generate_verification_reports", "view_team_dashboard", "update_deal_status"
            ],
            "Team Member": [
                "view_user", "view_own_clients", "create_client", "edit_client_details",
                "view_own_deals", "create_deal", "log_deal_activity",
                "view_own_teams", "view_own_projects", "view_own_commissions",
                "view_own_dashboard"
            ]
        }

        # Create system-wide role templates (organization=None)
        created_roles = 0
        for role_name, permission_codenames in default_roles_data.items():
            role, created = Role.objects.get_or_create(name=role_name, organization=None)
            
            if created:
                created_roles += 1
                
            # Always update permissions (in case new permissions were added)
            permissions_assigned = 0
            role.permissions.clear()  # Clear existing permissions
            
            for perm_codename in permission_codenames:
                try:
                    permission = Permission.objects.get(codename=perm_codename)
                    role.permissions.add(permission)
                    permissions_assigned += 1
                except Permission.DoesNotExist:
                    self.stdout.write(self.style.WARNING(f"⚠️ Permission '{perm_codename}' not found for role '{role_name}'"))
            
            status = "created" if created else "updated"
            self.stdout.write(self.style.SUCCESS(f"✅ Role '{role_name}' {status} with {permissions_assigned} permissions"))

        self.stdout.write(self.style.SUCCESS(f"🎭 {created_roles} new roles created, existing roles updated"))
        self.stdout.write(self.style.HTTP_INFO("📝 Available roles: Organization Admin, Sales Manager, Team Head, Senior Salesperson, Salesperson, Verifier, Team Member"))
        self.stdout.write(self.style.HTTP_INFO("💡 These are system-wide templates. Organizations can create their own instances.")) 