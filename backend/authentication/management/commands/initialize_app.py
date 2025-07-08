import os
import random
from datetime import timedelta
from decimal import Decimal

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from faker import Faker
from django.contrib.auth.models import Permission

from Verifier_dashboard.models import AuditLogs
from authentication.models import User
from clients.models import Client
from commission.models import Commission
from deals.models import Deal, Payment, PaymentApproval, PaymentInvoice, ActivityLog
from notifications.models import Notification, NotificationSettings
from organization.models import Organization
from permissions.models import Role
from project.models import Project
from team.models import Team

fake = Faker()

class Command(BaseCommand):
    help = "Initializes the application with a superuser and a rich, realistic mock dataset."

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🚀 Starting application initialization..."))
        self.stdout.write(self.style.WARNING("--- Flushing the database ---"))
        os.system('python manage.py flush --no-input')
        self.stdout.write(self.style.SUCCESS("✅ Database flushed."))
        
        # Ensure all permissions are recreated after flush
        self.stdout.write(self.style.WARNING("--- Recreating permissions ---"))
        os.system('python manage.py migrate')
        self.stdout.write(self.style.SUCCESS("✅ Permissions recreated."))

        # Set up notification templates
        self.stdout.write(self.style.WARNING("--- Setting up notification templates ---"))
        os.system('python manage.py setup_notification_templates')
        self.stdout.write(self.style.SUCCESS("✅ Notification templates created."))

        try:
            organization = self.create_organization()
            self.create_missing_permissions()
            users = self.create_users(organization)
            self.create_teams(organization, users)
            clients = self.create_clients(organization, users)
            projects = self.create_projects(users)
            
            self.create_deals_for_period(users, clients, projects, "historical", 60)
            self.create_deals_for_period(users, clients, projects, "recent", 25)
            
            if 'salestest' in users and [u for u in users.values() if u.role.name == 'Verifier']:
                self.create_streak_building_deals(users['salestest'], clients, projects, [u for u in users.values() if u.role.name == 'Verifier'])

            self.stdout.write(self.style.SUCCESS("✅ Application initialization completed successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ An error occurred during initialization: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))

    def create_organization(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Organization ---"))
        organization, created = Organization.objects.get_or_create(
            name="Innovate Inc.",
            defaults={'description': 'A leading innovation company'}
        )
        self.stdout.write(self.style.SUCCESS(f"🏢 Organization '{organization.name}' created."))
        return organization

    def create_missing_permissions(self):
        """Create missing permissions that views are checking for."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Missing Permissions ---"))
        
        from django.contrib.contenttypes.models import ContentType
        from deals.models import Deal
        from clients.models import Client
        from project.models import Project
        from team.models import Team
        from commission.models import Commission
        
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
        
        self.stdout.write(self.style.SUCCESS(f"✅ Created {created_count} new permissions!"))

    def create_users(self, organization):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Users and Roles ---"))
        role_permissions = self.get_role_permissions()
        for role_name, perms in role_permissions.items():
            role, _ = Role.objects.get_or_create(name=role_name, organization=None)
            permissions = Permission.objects.filter(codename__in=perms)
            role.permissions.set([p.pk for p in permissions])
            self.stdout.write(self.style.SUCCESS(f"  - Created role template '{role_name}' and assigned {len(perms)} permissions."))

        users = {}
        user_data = {
            "Super Admin": [("superadmin", "super@innovate.com")],
            "Organization Admin": [("orgadmin", "orgadmin@innovate.com")],
            "Salesperson": [("salestest", "sales@innovate.com"), ("salespro", "salespro@innovate.com")],
            "Verifier": [("verifier", "verifier@innovate.com")],
        }
        for role_name, user_list in user_data.items():
            org_role, _ = Role.objects.get_or_create(name=role_name, organization=organization)
            template_role = Role.objects.get(name=role_name, organization__isnull=True)
            org_role.permissions.set(template_role.permissions.all())
            for username, email in user_list:
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        'username': username,
                        'organization': organization if role_name != "Super Admin" else None, # Super Admin has no org
                        'role': org_role, 
                        'first_name': fake.first_name(), 
                        'last_name': fake.last_name(), 
                        'sales_target': Decimal(random.randint(25000, 75000)) if role_name == "Salesperson" else None
                    }
                )
                # Always set these attributes to ensure correctness on every run
                user.set_password("password123")
                user.is_active = True
                if role_name == "Super Admin":
                    user.is_superuser = True
                    user.is_staff = True
                    user.organization = None # Ensure superadmin is not tied to an org
                else:
                    user.organization = organization
                
                user.save()
                users[username] = user
                NotificationSettings.objects.get_or_create(user=user)

        self.stdout.write(self.style.SUCCESS("👥 Users, roles, and notification settings created."))
        return users

    def create_teams(self, organization, users):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Teams ---"))
        salespersons = [u for u in users.values() if u.role.name == 'Salesperson']
        if not salespersons:
            return

        team1 = Team.objects.create(name="Alpha Team", organization=organization, team_lead=salespersons[0], created_by=users['orgadmin'])
        team1.members.add(*salespersons[:len(salespersons)//2])
        
        if len(salespersons) > 1:
            team2 = Team.objects.create(name="Bravo Team", organization=organization, team_lead=salespersons[-1], created_by=users['orgadmin'])
            team2.members.add(*salespersons[len(salespersons)//2:])
            self.stdout.write(self.style.SUCCESS("✅ Created 2 sales teams."))
        else:
            self.stdout.write(self.style.SUCCESS("✅ Created 1 sales team."))

    def create_clients(self, organization, users):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Clients ---"))
        clients = []
        sales_users = [u for u in users.values() if u.role.name == 'Salesperson']
        for i in range(25):
            client = Client.objects.create(organization=organization, client_name=fake.company(), email=fake.unique.email(), phone_number=fake.phone_number(), created_by=random.choice(sales_users), satisfaction=random.choice(['neutral', 'satisfied', 'unsatisfied']))
            clients.append(client)
            if i < 3: # Make first 3 clients "loyal"
                client.status = 'clear'
                client.save()
        self.stdout.write(self.style.SUCCESS(f"👤 Created {len(clients)} clients."))
        return clients

    def create_projects(self, users):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Projects ---"))
        projects = [Project.objects.create(name=fake.catch_phrase(), description=fake.text(), created_by=random.choice(list(users.values()))) for _ in range(10)]
        self.stdout.write(self.style.SUCCESS(f"🏗️ Created {len(projects)} projects."))
        return projects

    def create_deals_for_period(self, users, clients, projects, period, count):
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating {count} {period.capitalize()} Deals ---"))
        salespersons = [u for u in users.values() if u.role.name == 'Salesperson']
        verifiers = [u for u in users.values() if u.role.name == 'Verifier']
        for i in range(count):
            now = timezone.now()
            deal_date = (now.date() - timedelta(days=random.randint(0, now.day - 1 if now.day > 1 else 0))) if period == "recent" else fake.date_between(start_date='-2y', end_date='-1M')
            deal = Deal.objects.create(organization=users['orgadmin'].organization, client=random.choice(clients), project=random.choice(projects) if projects and random.random() > 0.5 else None, deal_name=fake.bs().title(), deal_value=Decimal(random.randint(1000, 25000)), deal_date=deal_date, payment_method=random.choice([c[0] for c in Deal.PAYMENT_METHOD_CHOICES]), source_type=random.choice([c[0] for c in Deal.SOURCE_TYPES]), created_by=random.choice(salespersons))
            ActivityLog.objects.create(deal=deal, message=f"Deal created by {deal.created_by.username}.")
            
            if verifiers:
                scenario = random.choice(['verified_full', 'verified_partial', 'multi_partial', 'rejected', 'refunded', 'bad_debt'])
                if i < 5 and period == "recent": # Ensure some simple recent ones
                     scenario = 'verified_full'
                self.process_deal_payment_and_verification(deal, verifiers, scenario)

    def process_deal_payment_and_verification(self, deal, verifiers, scenario):
        verifier = random.choice(verifiers)
        payment_date = deal.deal_date + timedelta(days=random.randint(1, 10))
        
        if scenario == 'multi_partial':
            remaining_value = deal.deal_value
            for i in range(random.randint(2, 4)):
                if remaining_value <= 0: break
                payment_amount = (remaining_value / 2) * Decimal(random.uniform(0.5, 0.9))
                self.create_payment_flow(deal, payment_amount, payment_date + timedelta(days=i*10), verifier, 'verified' if i < 2 else 'pending')
                remaining_value -= payment_amount
            return

        payment_amount = deal.deal_value * Decimal(random.uniform(0.7, 1.0) if scenario == 'verified_full' else 0.5)
        self.create_payment_flow(deal, payment_amount, payment_date, verifier, scenario)
        
    def create_payment_flow(self, deal, amount, payment_date, verifier, final_status):
        payment = Payment.objects.create(deal=deal, received_amount=amount.quantize(Decimal('0.01')), payment_date=payment_date, payment_type=deal.payment_method)
        invoice = PaymentInvoice.objects.get(payment=payment)
        
        status_map = {'verified_full': 'verified', 'verified_partial': 'verified', 'rejected': 'rejected', 'refunded': 'refunded', 'bad_debt': 'bad_debt'}
        invoice.invoice_status = status_map.get(final_status, 'pending')
        
        if invoice.invoice_status == 'verified':
            deal.verification_status = 'verified'
            deal.payment_status = 'full_payment' if amount >= deal.deal_value else 'initial payment'
            action_text = "Verified"
            deal.client.status = 'clear'
        else:
            deal.verification_status = 'rejected'
            action_text = invoice.invoice_status.capitalize()
            if invoice.invoice_status == 'bad_debt':
                deal.client.status = 'bad_debt'

        PaymentApproval.objects.create(deal=deal, payment=payment, approved_by=verifier, approved_remarks=fake.sentence(), failure_remarks=None if invoice.invoice_status == 'verified' else "Details did not match.")
        
        deal.save()
        invoice.save()
        deal.client.save()

        ActivityLog.objects.create(deal=deal, message=f"Invoice {invoice.invoice_id} status updated to {invoice.invoice_status}.")
        AuditLogs.objects.create(user=verifier, organization=deal.organization, action=f"Invoice {action_text}", details=f"Invoice {invoice.invoice_id} for deal {deal.deal_id} was {action_text.lower()} by {verifier.username}.")
        Notification.objects.create(recipient=deal.created_by, organization=deal.organization, title=f"Deal {action_text}: {deal.deal_name}", message=f"The deal '{deal.deal_name}' has been {action_text.lower()}.", notification_type='deal_status_changed')
        
        if invoice.invoice_status == 'verified':
            start_of_month = deal.deal_date.replace(day=1)
            end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)
            commission = Commission.objects.create(user=deal.created_by, organization=deal.organization, total_sales=deal.deal_value, commission_rate=Decimal(random.uniform(3.0, 8.0)), start_date=start_of_month, end_date=end_of_month)
            Notification.objects.create(recipient=deal.created_by, organization=deal.organization, title="Commission Generated", message=f"You earned a commission of ${commission.commission_amount:,.2f} for deal {deal.deal_id}.", notification_type='commission_created')

    def create_streak_building_deals(self, salesperson, clients, projects, verifiers):
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating 5-day Deal Streak for {salesperson.username} ---"))
        today = timezone.now().date()
        for i in range(5):
            # Create deals for the last 5 consecutive days
            deal_date = today - timedelta(days=i)
            deal = Deal.objects.create(
                organization=salesperson.organization,
                client=random.choice(clients),
                project=random.choice(projects) if projects and random.random() > 0.5 else None,
                deal_name=f"Streak Deal Day {i+1}",
                deal_value=Decimal(random.randint(200, 1000)), # Ensure value is > 101
                deal_date=deal_date,
                payment_method='bank',
                source_type='referral',
                created_by=salesperson,
                # Set payment_status directly to meet streak criteria
                payment_status='initial payment',
                verification_status='verified' # Ensure it's verified
            )
            # Create the corresponding payment and invoice flow
            self.create_payment_flow(deal, deal.deal_value / 2, deal_date, random.choice(verifiers), 'verified')

    def get_role_permissions(self):
        # Dynamically fetch all permissions for relevant apps from Django's auth model
        all_perms = Permission.objects.select_related('content_type').all()
        
        # Give Salesperson ALL permissions for deals, clients, sales_dashboard, projects, team, commission
        salesperson_apps = ['deals', 'clients', 'Sales_dashboard', 'project', 'team', 'commission']
        salesperson_perms_codenames = [
            p.codename for p in all_perms if p.content_type.app_label in salesperson_apps
        ]
        
        # Give Verifier ALL permissions for deals, clients, Verifier_dashboard, invoices, payments
        verifier_apps = ['deals', 'clients', 'Verifier_dashboard']
        verifier_perms_codenames = [
            p.codename for p in all_perms if p.content_type.app_label in verifier_apps
        ]
        
        # Also add specific permissions that are checked in the permission classes
        salesperson_additional_perms = [
            'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 'delete_deal', 'log_deal_activity',
            'view_all_clients', 'view_own_clients', 'create_new_client', 'edit_client_details', 'remove_client',
            'view_all_teams', 'view_own_teams', 'create_new_team', 'edit_team_details', 'remove_team',
            'view_all_commissions', 'create_commission', 'edit_commission',
            'view_all_projects', 'view_own_projects', 'create_project', 'edit_project'
        ]
        
        verifier_additional_perms = [
            'view_all_deals', 'view_own_deals', 'verify_deal_payment', 'verify_payments',
            'view_all_clients', 'view_own_clients',
            'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
            'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
            'view_payment_verification_dashboard', 'view_payment_analytics', 'manage_invoices',
            'access_verification_queue', 'manage_refunds', 'view_audit_logs'
        ]
        # Ensure 'create_deal' is not present
        if 'create_deal' in verifier_additional_perms:
            verifier_additional_perms.remove('create_deal')
        
        # Combine dynamic permissions with specific ones
        final_salesperson_perms = list(set(salesperson_perms_codenames + salesperson_additional_perms))
        final_verifier_perms = list(set(verifier_perms_codenames + verifier_additional_perms))
        
        # Admin gets everything
        admin_perms_codenames = list(set(final_salesperson_perms + final_verifier_perms))
        
        return {
            "Super Admin": [p.codename for p in all_perms],
            "Organization Admin": admin_perms_codenames,
            "Salesperson": final_salesperson_perms,
            "Verifier": final_verifier_perms,
        }

    def create_user(self, username, email, password, first_name, last_name, organization, role, is_superuser=False):
        user, created = User.objects.get_or_create(email=email, defaults={'username': username, 'organization': organization, 'role': role, 'first_name': first_name, 'last_name': last_name, 'sales_target': Decimal(random.randint(25000, 75000)) if role.name == "Salesperson" else None})
        user.set_password(password)
        user.is_active = True
        if is_superuser:
            user.is_superuser = True
            user.is_staff = True
        user.save()
        NotificationSettings.objects.get_or_create(user=user)
        return user

    def assign_permissions_to_role(self, role, permissions):
        role.permissions.set(permissions)
        self.stdout.write(self.style.SUCCESS(f"  - Assigned {len(permissions)} permissions to role '{role.name}'."))