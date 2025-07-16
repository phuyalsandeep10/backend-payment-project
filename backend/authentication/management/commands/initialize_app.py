import os
import random
from datetime import timedelta
from django.core.management import call_command
from decimal import Decimal

from django.core.management.base import BaseCommand
from django.db import transaction, connection
from django.utils import timezone
from faker import Faker
from django.db.models.signals import post_save, post_delete
from deals.models import Deal, Payment, PaymentApproval, PaymentInvoice, ActivityLog
from Sales_dashboard.signals import update_streak_on_deal_delete
from notifications.signals import (
    notify_new_organization, notify_new_role, notify_new_user,
    notify_new_team, notify_new_client, notify_new_project,
    notify_payment_received, notify_deal_changes, notify_new_commission
)
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from authentication.models import User
from clients.models import Client
from commission.models import Commission
from notifications.models import Notification, NotificationSettings, NotificationTemplate
from organization.models import Organization
from permissions.models import Role
from project.models import Project
from team.models import Team
from Verifier_dashboard.models import AuditLogs
from Sales_dashboard.models import DailyStreakRecord

fake = Faker()

class Command(BaseCommand):
    help = "Initializes the application with a superuser and a rich, realistic mock dataset."

    def add_arguments(self, parser):
        parser.add_argument(
            '--flush',
            action='store_true',
            help='Flush all existing data before initializing (use with caution!)',
        )

    def handle(self, *args, **options):
        # Load JSON fixture if available before generating synthetic data
        fixture_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'initial_data.json')
        if os.path.exists(fixture_path):
            self.stdout.write(self.style.HTTP_INFO("--- Loading initial_data.json fixture ---"))
            try:
                call_command('loaddata', fixture_path, verbosity=0)
                self.stdout.write(self.style.SUCCESS("✅ initial_data.json loaded successfully"))
            except Exception as e:
                self.stdout.write(self.style.WARNING(f"⚠️ Could not load initial_data.json fixture: {e}"))
        self.stdout.write(self.style.SUCCESS("🚀 Starting application initialization..."))
        
        # Clean up duplicate permissions first
        self.cleanup_duplicate_permissions()
        
        # --- Disconnect all signals to prevent premature queries ---
        signals_to_disconnect = {
            post_save: [
                (notify_new_organization, Organization),
                (notify_new_role, Role),
                (notify_new_user, User),
                (notify_new_team, Team),
                (notify_new_client, Client),
                (notify_new_project, Project),
                (notify_payment_received, Payment),
                (notify_deal_changes, Deal),
                (notify_new_commission, Commission),
            ],
            post_delete: [
                # This signal was causing issues with raw TRUNCATE, but should be safe
                # with ORM-based deletion. Re-enabling it.
            ]
        }
        
        for signal, receivers in signals_to_disconnect.items():
            for receiver, sender in receivers:
                signal.disconnect(receiver, sender=sender)
        self.stdout.write(self.style.HTTP_INFO("  - All notification signals disconnected to prevent errors."))
        
        try:
            # Flush existing data if requested
            if options['flush']:
                self.flush_existing_data()
            
            # Each of these methods will now manage its own transaction.
            organization = self.create_organization()
            self.create_notification_templates()
            roles = self.create_roles_and_assign_permissions(organization)
            users = self.create_users(organization, roles)
            self.create_teams(organization, users)
            clients = self.create_clients(organization, users)
            projects = self.create_projects(users)
            self.create_deals_for_period(users, clients, projects, "historical", 60)
            self.create_deals_for_period(users, clients, projects, "recent", 25)
            
            # Create streak building deals
            salesperson = next((u for u in users.values() if u.username == 'salestest'), None)
            verifiers = [u for u in users.values() if u.role.name == 'Verifier']
            if salesperson and verifiers:
                self.create_streak_building_deals(salesperson, clients, projects, verifiers)

            self.stdout.write(self.style.SUCCESS("✅ Application initialization completed successfully!"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ An error occurred during initialization: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))
        finally:
            # --- Reconnect all signals ---
            for signal, receivers in signals_to_disconnect.items():
                for receiver, sender in receivers:
                    signal.connect(receiver, sender=sender)
            self.stdout.write(self.style.HTTP_INFO("  - All notification signals reconnected."))

    def flush_existing_data(self):
        """
        Flush all existing data from the database using the Django ORM to ensure
        all relations and signals are handled correctly.
        """
        self.stdout.write(self.style.WARNING("🗑️  Flushing existing data using Django's ORM..."))
        self.fallback_delete()
        self.stdout.write(self.style.SUCCESS("✅ Data flush completed."))

    def fallback_delete(self):
        """Deletes objects one by one to ensure signals and dependencies are handled."""
        try:
            # Start from objects that have the fewest dependencies
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Notifications & Settings..."))
            Notification.objects.all().delete()
            NotificationSettings.objects.all().delete()
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Dashboards & Logs..."))
            AuditLogs.objects.all().delete()
            ActivityLog.objects.all().delete()
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Payments & Invoices..."))
            PaymentApproval.objects.all().delete()
            PaymentInvoice.objects.all().delete()
            Payment.objects.all().delete()
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Commissions..."))
            Commission.objects.all().delete()
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Deals..."))
            Deal.objects.all().delete()
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Projects..."))
            Project.objects.all().delete()
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Clients..."))
            Client.objects.all().delete()
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Teams..."))
            Team.objects.all().delete()
            # Users and Roles have dependencies from many other models
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Users & Roles..."))
            User.objects.all().delete()
            Role.objects.all().delete()
            self.stdout.write(self.style.HTTP_INFO("  - Deleting Organizations..."))
            Organization.objects.all().delete()
            self.stdout.write(self.style.SUCCESS("✅ ORM-based deletion completed successfully."))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ ORM-based deletion failed: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))
            raise

    @transaction.atomic
    def create_organization(self):
        """Create the main organization."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Organization ---"))
        organization, created = Organization.objects.get_or_create(
            name="Innovate Inc.",
            defaults={'description': 'A leading innovation company'}
        )
        self.stdout.write(self.style.SUCCESS(f"🏢 Organization '{organization.name}' created."))
        return organization

    @transaction.atomic
    def create_notification_templates(self):
        """Create default notification templates."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Notification Templates ---"))
        
        templates = {
            'new_organization': {
                'title_template': "Welcome to the Platform!",
                'message_template': "A new organization, '{org_name}', has been registered.",
            },
            'role_created': {
                'title_template': "New Role Created: {role_name}",
                'message_template': "A new role named '{role_name}' has been created in your organization.",
            },
            'user_created': {
                'title_template': "Welcome, {user_name}!",
                'message_template': "A new user account has been created for you.",
            },
            'team_created': {
                'title_template': "New Team: {team_name}",
                'message_template': "A new team, '{team_name}', has been formed.",
            },
            'client_created': {
                'title_template': "New Client Added: {client_name}",
                'message_template': "A new client, {client_name}, has been added to the system.",
            },
            'project_created': {
                'title_template': "New Project Started: {project_name}",
                'message_template': "A new project, '{project_name}', has been initiated.",
            },
            'payment_received': {
                'title_template': "Payment Received for Deal: {deal_name}",
                'message_template': "A payment of {amount} has been received for the deal '{deal_name}'.",
            },
            'deal_status_changed': {
                'title_template': "Deal Status Updated: {deal_name}",
                'message_template': "The status of the deal '{deal_name}' has been updated to {status}.",
            },
            'commission_created': {
                'title_template': "You've Earned a Commission!",
                'message_template': "Congratulations! A commission of {amount} has been generated for you.",
            }
        }
        
        for notification_type, defaults in templates.items():
            template, created = NotificationTemplate.objects.get_or_create(
                notification_type=notification_type,
                defaults=defaults
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"  - Created template for '{notification_type}'"))
        
        self.stdout.write(self.style.SUCCESS("✅ Notification templates created."))

    @transaction.atomic
    def create_roles_and_assign_permissions(self, organization):
        """Create roles and assign all necessary permissions in one go."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Roles & Assigning Permissions ---"))
        
        roles = {}
        role_permissions = {
            "Super Admin": [
                # Super admin gets all permissions implicitly
            ],
            "Organization Admin": [
                # Full permissions across all key areas
                "add_deal", "view_deal", "change_deal", "delete_deal", "manage_invoices",
                "access_verification_queue", "verify_deal_payment", "manage_refunds", "verify_payments",
                "add_client", "view_client", "change_client", "delete_client",
                "add_user", "view_user", "change_user", "delete_user",
                "add_role", "view_role", "change_role", "delete_role",
                "change_organization", "view_organization",
                "add_project", "view_project", "change_project", "delete_project",
                "add_team", "view_team", "change_team", "delete_team",
                "add_commission", "view_commission", "change_commission", "delete_commission",
            ],
            "Salesperson": [
                # Deals
                "add_deal", "view_deal", "view_own_deals", "change_deal", "delete_deal",
                "add_payment", "view_payment", "change_payment", "delete_payment",
                "view_team_deals", "view_project_deals",
                # Clients
                "add_client", "view_client", "change_client", "delete_client",
                "create_new_client", "view_own_clients", "edit_client_details", "remove_client",
                # Teams
                "add_team", "view_team", "change_team", "delete_team", "view_own_teams",
                # Projects
                "add_project", "view_project", "change_project", "delete_project",
                # Approvals
                "view_paymentapproval", "create_paymentapproval", "edit_paymentapproval", "delete_paymentapproval",
                # Invoices
                "view_paymentinvoice", "create_paymentinvoice", "edit_paymentinvoice", "delete_paymentinvoice",
                # Dashboards
                "add_dailystreakrecord", "view_dailystreakrecord", "change_dailystreakrecord", "delete_dailystreakrecord",
                # Commissions
                "view_commission",
            ],
            "Verifier": [
                # Deals
                "add_deal", "view_deal", "change_deal", "delete_deal",
                "access_verification_queue", "verify_deal_payment", "verify_payments",
                # Payments
                "add_payment", "view_payment", "change_payment", "delete_payment",
                # Approvals
                "view_paymentapproval", "create_paymentapproval", "edit_paymentapproval", "delete_paymentapproval",
                # Invoices
                "view_paymentinvoice", "create_paymentinvoice", "edit_paymentinvoice", "delete_paymentinvoice",
                # Clients
                "add_client", "view_client", "change_client", "delete_client",
                # Projects
                "add_project", "view_project", "change_project", "delete_project",
                # Dashboards
                "view_payment_verification_dashboard", "view_payment_analytics", "view_audit_logs",
            ],
        }

        content_types = {
            "deal": ContentType.objects.get_for_model(Deal),
            "payment": ContentType.objects.get_for_model(Payment),
            "client": ContentType.objects.get_for_model(Client),
            "user": ContentType.objects.get_for_model(User),
            "role": ContentType.objects.get_for_model(Role),
            "organization": ContentType.objects.get_for_model(Organization),
            "project": ContentType.objects.get_for_model(Project),
            "team": ContentType.objects.get_for_model(Team),
            "commission": ContentType.objects.get_for_model(Commission),
            "dailystreakrecord": ContentType.objects.get_for_model(DailyStreakRecord),
            "auditlogs": ContentType.objects.get_for_model(AuditLogs),
        }

        # Define all org admin name variants
        org_admin_variants = [
            "Organization Admin", "Org Admin", "org-admin", "org admin", "orgadmin"
        ]

        for role_name, codenames in role_permissions.items():
            org_role, created = Role.objects.get_or_create(
                name=role_name, 
                organization=organization if role_name != "Super Admin" else None
            )
            
            if not created:
                org_role.permissions.clear()

            permissions_to_add = []
            for codename in codenames:
                try:
                    # Handle duplicate permissions by getting the first one
                    perm = Permission.objects.filter(codename=codename).first()
                    if perm:
                        permissions_to_add.append(perm)
                    else:
                        self.stdout.write(self.style.WARNING(f"  - WARNING: Permission '{codename}' not found. Skipping."))
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f"  - WARNING: Error getting permission '{codename}': {e}. Skipping."))

            if permissions_to_add:
                org_role.permissions.add(*permissions_to_add)
            
            roles[role_name] = org_role
            self.stdout.write(self.style.SUCCESS(f"  - Created role '{role_name}' and assigned {len(permissions_to_add)} permissions."))
            # If this is the canonical org admin role, assign permissions to all variants
            if role_name == "Organization Admin":
                for variant in org_admin_variants:
                    if variant == "Organization Admin":
                        continue
                    variant_role, _ = Role.objects.get_or_create(
                        name=variant,
                        organization=organization
                    )
                    variant_role.permissions.set(permissions_to_add)
                    self.stdout.write(self.style.SUCCESS(f"  - Synced permissions to org admin variant role '{variant}'"))
        
        return roles

    @transaction.atomic
    def create_users(self, organization, roles):
        """Create users with appropriate roles."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Users ---"))

        users = {}
        user_data = {
            "Super Admin": [("superadmin", "super@innovate.com")],
            "Organization Admin": [("orgadmin", "orgadmin@innovate.com")],
            "Salesperson": [("salestest", "sales@innovate.com"), ("salespro", "salespro@innovate.com")],
            "Verifier": [("verifier", "verifier@innovate.com")],
        }
        
        for role_name, user_list in user_data.items():
            org_role = roles[role_name]
            
            for username, email in user_list:
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        'username': username,
                        'organization': organization if role_name != "Super Admin" else None,
                        'role': org_role, 
                        'first_name': fake.first_name(), 
                        'last_name': fake.last_name(), 
                        'sales_target': Decimal(random.randint(25000, 75000)) if role_name == "Salesperson" else Decimal('0.00')
                    }
                )
                
                # Ensure role is assigned even for existing users
                if not created and user.role != org_role:
                    user.role = org_role
                    user.save(update_fields=['role'])
                
                # Set password and permissions
                user.set_password("password123")
                user.is_active = True
                
                if role_name == "Super Admin":
                    user.is_superuser = True
                    user.is_staff = True
                    user.organization = None
                else:
                    user.organization = organization
                
                user.save()
                users[username] = user
                
                # Create notification settings
                NotificationSettings.objects.get_or_create(user=user)

                self.stdout.write(self.style.SUCCESS(f"  - Created user: {username} ({role_name})"))
        
        return users

    @transaction.atomic
    def create_teams(self, organization, users):
        """Create sales teams."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Teams ---"))
        
        salespersons = [u for u in users.values() if u.role and u.role.name == 'Salesperson']
        if not salespersons:
            self.stdout.write(self.style.WARNING("  - No salespersons found, skipping team creation."))
            return

        org_admin = next((u for u in users.values() if u.role and u.role.name == 'Organization Admin'), None)
        if not org_admin:
            self.stdout.write(self.style.WARNING("  - Org Admin not found, cannot create teams."))
            return

        team1 = Team.objects.create(
            name="Alpha Team", 
            organization=organization, 
            team_lead=salespersons[0], 
            created_by=org_admin
        )
        team1.members.add(*salespersons[:len(salespersons)//2])
        
        self.stdout.write(self.style.SUCCESS("  - Created team: Alpha Team"))

        if len(salespersons) > 1:
            team2 = Team.objects.create(
                name="Bravo Team",
                organization=organization,
                team_lead=salespersons[-1],
                created_by=org_admin
            )
            team2.members.add(*salespersons[len(salespersons)//2:])
            self.stdout.write(self.style.SUCCESS("  - Created team: Bravo Team"))

    @transaction.atomic
    def create_clients(self, organization, users):
        """Create clients."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Clients ---"))
        
        clients = []
        sales_users = [u for u in users.values() if u.role and u.role.name == 'Salesperson']
        
        for i in range(25):
            client = Client.objects.create(
                organization=organization,
                client_name=f"{fake.company()} {fake.company_suffix()}",
                email=fake.unique.email(),
                phone_number=fake.phone_number(),
                created_by=random.choice(sales_users),
                satisfaction=random.choice(['neutral', 'satisfied', 'unsatisfied'])
            )
            clients.append(client)
            
            # Make first 3 clients "loyal"
            if i < 3:
                client.status = 'loyal'
                client.save()
        
        self.stdout.write(self.style.SUCCESS(f"👤 Created {len(clients)} clients."))
        return clients

    @transaction.atomic
    def create_projects(self, users):
        """Create projects."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Projects ---"))
        
        projects = []
        for _ in range(10):
            project = Project.objects.create(
                name=fake.catch_phrase(),
                description=f"{fake.catch_phrase()}. {fake.text(max_nb_chars=200)}",
                created_by=random.choice(list(users.values()))
            )
            projects.append(project)
        
        self.stdout.write(self.style.SUCCESS(f"🏗️ Created {len(projects)} projects."))
        return projects

    @transaction.atomic
    def create_deals_for_period(self, users, clients, projects, period, count):
        """Create deals for a specific period."""
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating {count} {period.capitalize()} Deals ---"))
        
        salespersons = [u for u in users.values() if u.role and u.role.name == 'Salesperson']
        verifiers = [u for u in users.values() if u.role and u.role.name == 'Verifier']
        
        for i in range(count):
            # Determine deal date based on period
            if period == "recent":
                now = timezone.now()
                deal_date = now.date() - timedelta(days=random.randint(0, min(now.day - 1, 30)))
                if deal_date < now.date() - timedelta(days=30):
                    deal_date = now.date() - timedelta(days=30)
            else:
                deal_date = fake.date_between(start_date='-2y', end_date='-1M')
            
            sales_user = random.choice(salespersons) if salespersons else None
            if not sales_user:
                continue

            # Create deal
            deal = Deal.objects.create(
                organization=sales_user.organization,
                client=random.choice(clients),
                project=random.choice(projects) if projects and random.random() > 0.5 else None,
                deal_name=fake.bs().title(),
                deal_value=Decimal(random.randint(1000, 25000)),
                deal_date=deal_date,
                payment_method=random.choice([c[0] for c in Deal.PAYMENT_METHOD_CHOICES]),
                source_type=random.choice([c[0] for c in Deal.SOURCE_TYPES]),
                created_by=sales_user
            )
            
            # Create activity log
            ActivityLog.objects.create(
                deal=deal, 
                message=f"Deal '{deal.deal_name}' created by {deal.created_by.username} for {deal.client.client_name}."
            )
            
            # Process payment and verification if verifiers exist
            if verifiers:
                scenario = random.choice(['verified_full', 'verified_partial', 'multi_partial', 'rejected', 'refunded', 'bad_debt'])
                if i < 5 and period == "recent":
                     scenario = 'verified_full'
                self.process_deal_payment_and_verification(deal, verifiers, scenario)

    def process_deal_payment_and_verification(self, deal, verifiers, scenario):
        """Process payment and verification for a deal."""
        verifier = random.choice(verifiers)
        payment_date = deal.deal_date + timedelta(days=random.randint(1, 10))
        
        if scenario == 'multi_partial':
            remaining_value = deal.deal_value
            for i in range(random.randint(2, 4)):
                if remaining_value <= 0:
                    break
                payment_amount = (remaining_value / 2) * Decimal(random.uniform(0.5, 0.9))
                self.create_payment_flow(deal, payment_amount, payment_date + timedelta(days=i*10), verifier, 'verified' if i < 2 else 'pending')
                remaining_value -= payment_amount
            return

        payment_amount = deal.deal_value * Decimal(random.uniform(0.7, 1.0) if scenario == 'verified_full' else 0.5)
        self.create_payment_flow(deal, payment_amount, payment_date, verifier, scenario)
        
    def create_payment_flow(self, deal, amount, payment_date, verifier, final_status):
        """Create payment flow for a deal."""
        # Create payment
        payment = Payment.objects.create(
            deal=deal,
            received_amount=amount.quantize(Decimal('0.01')),
            payment_date=payment_date,
            payment_type=deal.payment_method  # Use the deal's payment method as payment type
        )
        
        # Get or create invoice
        invoice, _ = PaymentInvoice.objects.get_or_create(payment=payment, deal=deal)
        
        # Map status
        status_map = {
            'verified_full': 'verified',
            'verified_partial': 'verified',
            'rejected': 'rejected',
            'refunded': 'refunded',
            'bad_debt': 'bad_debt'
        }
        invoice.invoice_status = status_map.get(final_status, 'pending')
        
        # Update deal and client status
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

        # Create payment approval
        PaymentApproval.objects.create(
            deal=deal,
            payment=payment,
            approved_by=verifier,
            verifier_remarks=fake.sentence(),
            failure_remarks=None if invoice.invoice_status == 'verified' else "Details did not match."
        )
        
        # Save changes
        deal.save()
        invoice.save()
        deal.client.save()

        # Create activity log
        ActivityLog.objects.create(
            deal=deal,
            message=f"Invoice {invoice.invoice_id} status updated to {invoice.invoice_status}."
        )
        
        # Create audit log
        AuditLogs.objects.create(
            user=verifier,
            organization=deal.organization,
            action=f"Invoice {action_text}",
            details=f"Invoice {invoice.invoice_id} for deal {deal.deal_id} was {action_text.lower()} by {verifier.username}."
        )
        
        # Create notification
        Notification.objects.create(
            recipient=deal.created_by,
            organization=deal.organization,
            title=f"Deal {action_text}: {deal.deal_name}",
            message=f"The deal '{deal.deal_name}' has been {action_text.lower()}.",
            notification_type='deal_status_changed'
        )
        
        # Create commission if verified
        if invoice.invoice_status == 'verified':
            start_of_month = deal.deal_date.replace(day=1)
            end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)
            
            commission = Commission.objects.create(
                user=deal.created_by,
                organization=deal.organization,
                total_sales=deal.deal_value,
                commission_rate=Decimal(random.uniform(3.0, 8.0)),
                start_date=start_of_month,
                end_date=end_of_month
            )
            
            Notification.objects.create(
                recipient=deal.created_by,
                organization=deal.organization,
                title="Commission Generated",
                message=f"You earned a commission of ${commission.commission_amount:,.2f} for deal {deal.deal_id}.",
                notification_type='commission_created'
            )

    @transaction.atomic
    def create_streak_building_deals(self, salesperson, clients, projects, verifiers):
        """Create streak building deals for a salesperson."""
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating 5-day Deal Streak for {salesperson.username} ---"))
        
        today = timezone.now().date()
        for i in range(5):
            deal_date = today - timedelta(days=i)
            
            deal = Deal.objects.create(
                organization=salesperson.organization,
                client=random.choice(clients),
                project=random.choice(projects) if projects and random.random() > 0.5 else None,
                deal_name=f"Streak Deal Day {i+1}",
                deal_value=Decimal(random.randint(200, 1000)),
                deal_date=deal_date,
                payment_method='bank',
                source_type='referral',
                created_by=salesperson,
                payment_status='initial payment',
                verification_status='verified'
            )
            
            # Create payment flow
            self.create_payment_flow(deal, deal.deal_value / 2, deal_date, random.choice(verifiers), 'verified')

    def assign_critical_permissions_fallback(self, organization, roles):
        """A simplified fallback to ensure critical roles have basic permissions if the main method fails."""
        self.stdout.write(self.style.HTTP_INFO("--- Assigning Critical Permissions (Fallback) ---"))
        
        # Simplified permissions for fallback
        fallback_perms = {
            "Organization Admin": ["add_user", "add_role", "add_client", "add_deal"],
            "Salesperson": ["add_deal", "add_payment", "add_client"],
            "Verifier": ["view_deal", "verify_deal_payment"]
        }
        
        for role_name, codenames in fallback_perms.items():
            if role_name in roles:
                role = roles[role_name]
                for codename in codenames:
                    try:
                        perm = Permission.objects.get(codename=codename)
                        role.permissions.add(perm)
                        self.stdout.write(self.style.SUCCESS(f"  - Fallback: Assigned '{codename}' to '{role_name}'"))
                    except Permission.DoesNotExist:
                        self.stdout.write(self.style.WARNING(f"  - Fallback WARNING: Permission '{codename}' not found. Skipping."))

    def cleanup_duplicate_permissions(self):
        """Clean up duplicate permissions before initialization."""
        self.stdout.write(self.style.HTTP_INFO("--- Cleaning up duplicate permissions ---"))
        
        from django.db import connection
        
        try:
            with connection.cursor() as cursor:
                # Find and delete duplicate permissions, keeping the one with the lowest ID
                cursor.execute("""
                    DELETE FROM auth_permission 
                    WHERE id NOT IN (
                        SELECT MIN(id) 
                        FROM auth_permission 
                        GROUP BY codename, content_type_id
                    )
                """)
                
                deleted_count = cursor.rowcount
                if deleted_count > 0:
                    self.stdout.write(self.style.SUCCESS(f"  - Removed {deleted_count} duplicate permissions"))
                else:
                    self.stdout.write(self.style.SUCCESS("  - No duplicate permissions found"))
                    
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"  - Warning: Could not clean up duplicate permissions: {e}"))
            # Continue with initialization even if cleanup fails