from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from deals.models import Deal
from clients.models import Client
from project.models import Project
from team.models import Team
from commission.models import Commission
from Verifier_dashboard.models import AuditLogs
from notifications.models import Notification

class Command(BaseCommand):
    help = 'Create all missing permissions that the role assignment script needs'

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("=== Creating All Missing Permissions ==="))
        
        # Get content types
        deal_ct = ContentType.objects.get_for_model(Deal)
        client_ct = ContentType.objects.get_for_model(Client)
        project_ct = ContentType.objects.get_for_model(Project)
        team_ct = ContentType.objects.get_for_model(Team)
        commission_ct = ContentType.objects.get_for_model(Commission)
        audit_log_ct = ContentType.objects.get_for_model(AuditLogs)
        notification_ct = ContentType.objects.get_for_model(Notification)
        
        # Define all permissions to create
        permissions_to_create = [
            # Deal permissions
            ('view_all_deals', 'Can view all deals', deal_ct),
            ('view_own_deals', 'Can view own deals', deal_ct),
            ('create_deal', 'Can create deal', deal_ct),
            ('edit_deal', 'Can edit deal', deal_ct),
            ('delete_deal', 'Can delete deal', deal_ct),
            ('log_deal_activity', 'Can log deal activity', deal_ct),
            ('verify_deal_payment', 'Can verify deal payment', deal_ct),
            ('verify_payments', 'Can verify payments', deal_ct),
            ('manage_invoices', 'Can manage invoices', deal_ct),
            ('access_verification_queue', 'Can access verification queue', deal_ct),
            ('manage_refunds', 'Can manage refunds', deal_ct),
            
            # Client permissions
            ('view_all_clients', 'Can view all clients', client_ct),
            ('view_own_clients', 'Can view own clients', client_ct),
            ('create_new_client', 'Can create new client', client_ct),
            ('edit_client_details', 'Can edit client details', client_ct),
            ('remove_client', 'Can remove client', client_ct),
            
            # Team permissions
            ('view_all_teams', 'Can view all teams', team_ct),
            ('view_own_teams', 'Can view own teams', team_ct),
            ('create_new_team', 'Can create new team', team_ct),
            ('edit_team_details', 'Can edit team details', team_ct),
            ('remove_team', 'Can remove team', team_ct),
            
            # Commission permissions
            ('view_all_commissions', 'Can view all commissions', commission_ct),
            ('create_commission', 'Can create commission', commission_ct),
            ('edit_commission', 'Can edit commission', commission_ct),
            
            # Project permissions
            ('view_all_projects', 'Can view all projects', project_ct),
            ('view_own_projects', 'Can view own projects', project_ct),
            ('create_project', 'Can create project', project_ct),
            ('edit_project', 'Can edit project', project_ct),
            ('delete_project', 'Can delete project', project_ct),
            
            # Payment invoice permissions
            ('view_paymentinvoice', 'Can view payment invoice', deal_ct),
            ('create_paymentinvoice', 'Can create payment invoice', deal_ct),
            ('edit_paymentinvoice', 'Can edit payment invoice', deal_ct),
            ('delete_paymentinvoice', 'Can delete payment invoice', deal_ct),
            
            # Payment approval permissions
            ('view_paymentapproval', 'Can view payment approval', deal_ct),
            ('create_paymentapproval', 'Can create payment approval', deal_ct),
            ('edit_paymentapproval', 'Can edit payment approval', deal_ct),
            ('delete_paymentapproval', 'Can delete payment approval', deal_ct),
            
            # Verifier dashboard permissions
            ('view_payment_verification_dashboard', 'Can view payment verification dashboard', audit_log_ct),
            ('view_payment_analytics', 'Can view payment analytics', audit_log_ct),
            ('view_audit_logs', 'Can view audit logs', audit_log_ct),
            
            # Role management permissions
            ('can_manage_roles', 'Can manage roles', audit_log_ct),  # Using audit_log_ct as content type
        ]
        
        created_count = 0
        for codename, name, content_type in permissions_to_create:
            try:
                perm, created = Permission.objects.get_or_create(
                    codename=codename,
                    content_type=content_type,
                    defaults={'name': name}
                )
                if created:
                    created_count += 1
                    self.stdout.write(f"✅ Created permission: {codename}")
                else:
                    self.stdout.write(f"ℹ️  Permission already exists: {codename}")
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Error creating permission {codename}: {e}"))
        
        self.stdout.write(self.style.SUCCESS(f"✅ Created {created_count} new permissions!"))
        
        # Also create standard Django permissions for all models
        self.stdout.write(self.style.HTTP_INFO("=== Creating Standard Django Permissions ==="))
        
        models_to_check = [
            (Deal, deal_ct),
            (Client, client_ct),
            (Project, project_ct),
            (Team, team_ct),
            (Commission, commission_ct),
            (AuditLogs, audit_log_ct),
            (Notification, notification_ct),
        ]
        
        standard_permissions = ['add', 'change', 'delete', 'view']
        standard_created = 0
        
        for model, content_type in models_to_check:
            for perm in standard_permissions:
                try:
                    perm_obj, created = Permission.objects.get_or_create(
                        codename=f'{perm}_{model._meta.model_name}',
                        content_type=content_type,
                        defaults={'name': f'Can {perm} {model._meta.verbose_name}'}
                    )
                    if created:
                        standard_created += 1
                        self.stdout.write(f"✅ Created standard permission: {perm}_{model._meta.model_name}")
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"❌ Error creating standard permission {perm}_{model._meta.model_name}: {e}"))
        
        self.stdout.write(self.style.SUCCESS(f"✅ Created {standard_created} standard permissions!"))
        self.stdout.write(self.style.SUCCESS(f"🎉 Total permissions created: {created_count + standard_created}")) 