from apps.permissions.models import Role
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

def assign_all_permissions_to_roles(organization, role_names=None, stdout=None):
    """
    Assign all relevant permissions to all roles for the given organization.
    If role_names is None, assign to all standard roles.
    """
    if role_names is None:
        role_names = ["Super Admin", "Organization Admin", "Salesperson", "Verifier"]

    def log(msg):
        if stdout:
            stdout.write(msg)

    for role_name in role_names:
        try:
            role, created = Role.objects.get_or_create(
                name=role_name,
                organization=organization if role_name != "Super Admin" else None
            )
            if created:
                log(f"  - Created role: {role_name}")
            else:
                log(f"  - Found existing role: {role_name}")

            # Get permissions for this role
            permissions = get_permissions_for_role(role_name)

            if not permissions:
                log(f"  - No permissions found for role: {role_name}")
                continue

            # Clear existing permissions and assign new ones
            role.permissions.clear()
            try:
                role.permissions.add(*permissions)
                log(f"  ✅ Assigned {len(permissions)} permissions to {role_name}")
            except Exception as e:
                log(f"  ❌ Error adding permissions to role {role_name}: {e}")
                # Try to add permissions one by one to identify the problematic one
                for perm in permissions:
                    try:
                        role.permissions.add(perm)
                    except Exception as perm_error:
                        log(f"    ❌ Failed to add permission {perm.codename}: {perm_error}")
        except Exception as e:
            log(f"  ❌ Error assigning permissions to {role_name}: {e}")

def get_permissions_for_role(role_name):
    """Get the list of permissions for a specific role."""
    if role_name == "Super Admin":
        try:
            return list(Permission.objects.all())
        except Exception:
            return []
    elif role_name == "Organization Admin":
        return get_org_admin_permissions()
    elif role_name == "Salesperson":
        return get_salesperson_permissions()
    elif role_name == "Verifier":
        return get_verifier_permissions()
    return []

def safe_get_permissions(codenames):
    existing_permissions = []
    for codename in codenames:
        try:
            permission = Permission.objects.filter(codename=codename).first()
            if permission:
                existing_permissions.append(permission)
        except Exception:
            pass
    return existing_permissions

def get_org_admin_permissions():
    user_permissions = [
        'add_user', 'change_user', 'delete_user', 'view_user',
    ]
    client_permissions = [
        'add_client', 'change_client', 'delete_client', 'view_client',
        'view_all_clients', 'view_own_clients', 'create_new_client', 
        'edit_client_details', 'remove_client'
    ]
    deal_permissions = [
        'add_deal', 'change_deal', 'delete_deal', 'view_deal',
        'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 
        'delete_deal', 'log_deal_activity', 'verify_deal_payment', 
        'verify_payments', 'manage_invoices', 'access_verification_queue',
        'manage_refunds'
    ]
    project_permissions = [
        'add_project', 'change_project', 'delete_project', 'view_project',
        'view_all_projects', 'view_own_projects', 'create_project', 
        'edit_project', 'delete_project'
    ]
    team_permissions = [
        'add_team', 'change_team', 'delete_team', 'view_team',
        'view_all_teams', 'view_own_teams', 'create_new_team', 
        'edit_team_details', 'remove_team'
    ]
    commission_permissions = [
        'add_commission', 'change_commission', 'delete_commission', 'view_commission',
        'view_all_commissions', 'create_commission', 'edit_commission'
    ]
    payment_invoice_permissions = [
        'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 
        'delete_paymentinvoice'
    ]
    payment_approval_permissions = [
        'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 
        'delete_paymentapproval'
    ]
    notification_permissions = [
        'add_notification', 'change_notification', 'delete_notification', 'view_notification'
    ]
    audit_log_permissions = [
        'view_audit_logs', 'view_payment_verification_dashboard', 'view_payment_analytics'
    ]
    role_management_permissions = [
        'can_manage_roles'
    ]
    all_permission_codenames = (
        user_permissions + client_permissions + deal_permissions + 
        project_permissions + team_permissions + commission_permissions +
        payment_invoice_permissions + payment_approval_permissions +
        notification_permissions + audit_log_permissions + role_management_permissions
    )
    return safe_get_permissions(all_permission_codenames)

def get_salesperson_permissions():
    client_permissions = [
        'view_own_clients', 'create_new_client', 
        'edit_client_details', 'remove_client'
    ]
    deal_permissions = [
        'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 
        'delete_deal', 'log_deal_activity'
    ]
    project_permissions = [
        'view_all_projects', 'view_own_projects', 'create_project', 
        'edit_project', 'delete_project'
    ]
    team_permissions = [
        'view_all_teams', 'view_own_teams', 'create_new_team', 
        'edit_team_details', 'remove_team'
    ]
    commission_permissions = [
        'view_commission', 'view_all_commissions', 'create_commission', 'edit_commission'
    ]
    payment_permissions = [
        'create_deal_payment',
    ]
    all_permission_codenames = (
        client_permissions + deal_permissions + project_permissions +
        team_permissions + commission_permissions + payment_permissions
    )
    return safe_get_permissions(all_permission_codenames)

def get_verifier_permissions():
    # Add verifier-specific permissions as needed
    verifier_permissions = [
        'verify_deal_payment', 'access_verification_queue', 'view_audit_logs',
        'view_payment_verification_dashboard', 'view_payment_analytics'
    ]
    return safe_get_permissions(verifier_permissions) 