from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from apps.deals.models import Deal
from apps.clients.models import Client
from apps.project.models import Project
from apps.team.models import Team
from commission.models import Commission

class Command(BaseCommand):
    help = 'Create missing deal permissions that views are checking for'

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("=== Creating Missing Deal Permissions ==="))
        
        # Get content types
        deal_ct = ContentType.objects.get_for_model(Deal)
        client_ct = ContentType.objects.get_for_model(Client)
        project_ct = ContentType.objects.get_for_model(Project)
        team_ct = ContentType.objects.get_for_model(Team)
        commission_ct = ContentType.objects.get_for_model(Commission)
        
        # Define permissions to create
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
        ]
        
        created_count = 0
        for codename, name, content_type in permissions_to_create:
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
        
        self.stdout.write(self.style.SUCCESS(f"✅ Created {created_count} new permissions!")) 