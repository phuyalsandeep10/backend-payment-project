import os
import random
from datetime import timedelta
from decimal import Decimal

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from faker import Faker

from authentication.models import User
from clients.models import Client
from commission.models import Commission
from deals.models import Deal, Payment, PaymentApproval, PaymentInvoice, ActivityLog
from notifications.models import Notification, NotificationSettings
from organization.models import Organization
from permissions.models import Role
from project.models import Project
from team.models import Team
from Verifier_dashboard.models import AuditLogs

fake = Faker()

class Command(BaseCommand):
    help = "Initializes the application with a superuser and a rich, realistic mock dataset."

    def add_arguments(self, parser):
        parser.add_argument(
            '--flush',
            action='store_true',
            help='Flush all existing data before initializing (use with caution!)',
        )

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🚀 Starting application initialization..."))
        
        # Flush existing data if requested
        if options['flush']:
            self.flush_existing_data()
        
        try:
            # Create organization
            organization = self.create_organization()
            
            # Create roles (without assigning permissions - let Django handle this)
            roles = self.create_roles(organization)
            
            # Create users
            users = self.create_users(organization, roles)
            
            # Assign permissions to roles
            self.assign_permissions_to_roles(organization, roles)
            
            # Create teams
            self.create_teams(organization, users)
            
            # Create clients
            clients = self.create_clients(organization, users)
            
            # Create projects
            projects = self.create_projects(users)
            
            # Create deals
            self.create_deals_for_period(users, clients, projects, "historical", 60)
            self.create_deals_for_period(users, clients, projects, "recent", 25)
            
            # Create streak building deals
            if 'salestest' in users and any(u.role.name == 'Verifier' for u in users.values()):
                verifiers = [u for u in users.values() if u.role.name == 'Verifier']
                self.create_streak_building_deals(users['salestest'], clients, projects, verifiers)

            self.stdout.write(self.style.SUCCESS("✅ Application initialization completed successfully!"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ An error occurred during initialization: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))

    def flush_existing_data(self):
        """Flush all existing data from the database."""
        self.stdout.write(self.style.WARNING("🗑️  Flushing existing data..."))
        
        try:
            # Import all models that need to be flushed
            from authentication.models import User
            from clients.models import Client
            from commission.models import Commission
            from deals.models import Deal, Payment, PaymentApproval, PaymentInvoice, ActivityLog
            from notifications.models import Notification, NotificationSettings
            from organization.models import Organization
            from permissions.models import Role
            from project.models import Project
            from team.models import Team
            from Verifier_dashboard.models import AuditLogs
            
            # Delete data in reverse dependency order
            self.stdout.write("  - Deleting notifications...")
            Notification.objects.all().delete()
            NotificationSettings.objects.all().delete()
            
            self.stdout.write("  - Deleting audit logs...")
            AuditLogs.objects.all().delete()
            
            self.stdout.write("  - Deleting activity logs...")
            ActivityLog.objects.all().delete()
            
            self.stdout.write("  - Deleting payment approvals...")
            PaymentApproval.objects.all().delete()
            
            self.stdout.write("  - Deleting payment invoices...")
            PaymentInvoice.objects.all().delete()
            
            self.stdout.write("  - Deleting payments...")
            Payment.objects.all().delete()
            
            self.stdout.write("  - Deleting commissions...")
            Commission.objects.all().delete()
            
            self.stdout.write("  - Deleting deals...")
            Deal.objects.all().delete()
            
            self.stdout.write("  - Deleting projects...")
            Project.objects.all().delete()
            
            self.stdout.write("  - Deleting clients...")
            Client.objects.all().delete()
            
            self.stdout.write("  - Deleting teams...")
            Team.objects.all().delete()
            
            self.stdout.write("  - Deleting users...")
            User.objects.all().delete()
            
            self.stdout.write("  - Deleting roles...")
            Role.objects.all().delete()
            
            self.stdout.write("  - Deleting organizations...")
            Organization.objects.all().delete()
            
            self.stdout.write(self.style.SUCCESS("✅ All existing data flushed successfully!"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error flushing data: {e}"))
            raise

    def create_organization(self):
        """Create the main organization."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Organization ---"))
        organization, created = Organization.objects.get_or_create(
            name="Innovate Inc.",
            defaults={'description': 'A leading innovation company'}
        )
        self.stdout.write(self.style.SUCCESS(f"🏢 Organization '{organization.name}' created."))
        return organization

    def create_roles(self, organization):
        """Create roles without assigning permissions."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Roles ---"))
        
        roles = {}
        role_names = ["Super Admin", "Organization Admin", "Salesperson", "Verifier"]
        
        for role_name in role_names:
            # Create template role (no organization)
            template_role, _ = Role.objects.get_or_create(
                name=role_name, 
                organization=None
            )
            
            # Create organization-specific role
            org_role, _ = Role.objects.get_or_create(
                name=role_name, 
                organization=organization
            )
            
            roles[role_name] = {
                'template': template_role,
                'organization': org_role
            }
        
            self.stdout.write(self.style.SUCCESS(f"  - Created role: {role_name}"))
        
        return roles

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
            org_role = roles[role_name]['organization']
            
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

    def create_teams(self, organization, users):
        """Create sales teams."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Teams ---"))
        
        salespersons = [u for u in users.values() if u.role.name == 'Salesperson']
        if not salespersons:
            return

        team1 = Team.objects.create(
            name="Alpha Team", 
            organization=organization, 
            team_lead=salespersons[0], 
            created_by=users['orgadmin']
        )
        team1.members.add(*salespersons[:len(salespersons)//2])
        
        if len(salespersons) > 1:
            team2 = Team.objects.create(
                name="Bravo Team", 
                organization=organization, 
                team_lead=salespersons[-1], 
                created_by=users['orgadmin']
            )
            team2.members.add(*salespersons[len(salespersons)//2:])
            self.stdout.write(self.style.SUCCESS("✅ Created 2 sales teams."))
        else:
            self.stdout.write(self.style.SUCCESS("✅ Created 1 sales team."))

    def create_clients(self, organization, users):
        """Create clients."""
        self.stdout.write(self.style.HTTP_INFO("--- Creating Clients ---"))
        
        clients = []
        sales_users = [u for u in users.values() if u.role.name == 'Salesperson']
        
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
                client.status = 'clear'
                client.save()
        
        self.stdout.write(self.style.SUCCESS(f"👤 Created {len(clients)} clients."))
        return clients

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

    def create_deals_for_period(self, users, clients, projects, period, count):
        """Create deals for a specific period."""
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating {count} {period.capitalize()} Deals ---"))
        
        salespersons = [u for u in users.values() if u.role.name == 'Salesperson']
        verifiers = [u for u in users.values() if u.role.name == 'Verifier']
        
        for i in range(count):
            # Determine deal date based on period
            if period == "recent":
                now = timezone.now()
                deal_date = now.date() - timedelta(days=random.randint(0, min(now.day - 1, 30)))
                if deal_date < now.date() - timedelta(days=30):
                    deal_date = now.date() - timedelta(days=30)
            else:
                deal_date = fake.date_between(start_date='-2y', end_date='-1M')
            
            # Create deal
            deal = Deal.objects.create(
                organization=users['orgadmin'].organization,
                client=random.choice(clients),
                project=random.choice(projects) if projects and random.random() > 0.5 else None,
                deal_name=fake.bs().title(),
                deal_value=Decimal(random.randint(1000, 25000)),
                deal_date=deal_date,
                payment_method=random.choice([c[0] for c in Deal.PAYMENT_METHOD_CHOICES]),
                source_type=random.choice([c[0] for c in Deal.SOURCE_TYPES]),
                created_by=random.choice(salespersons)
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
            payment_type=deal.payment_method
        )
        
        # Get or create invoice
        invoice = PaymentInvoice.objects.get(payment=payment)
        
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
            approved_remarks=fake.sentence(),
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

    def assign_permissions_to_roles(self, organization, roles):
        """Assign proper permissions to roles based on their responsibilities."""
        self.stdout.write(self.style.HTTP_INFO("--- Assigning Permissions to Roles ---"))
        
        # Import the assign_role_permissions command
        from django.core.management import call_command
        
        try:
            # Call the assign_role_permissions command for this organization
            call_command('assign_role_permissions', organization=organization.name)
            self.stdout.write(self.style.SUCCESS("✅ Permissions assigned successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error assigning permissions: {e}"))
            # Fallback: manually assign critical permissions
            self.assign_critical_permissions_fallback(organization, roles)
    
    def assign_critical_permissions_fallback(self, organization, roles):
        """Fallback method to assign critical permissions if the main command fails."""
        self.stdout.write(self.style.WARNING("⚠️  Using fallback permission assignment..."))
        
        from django.contrib.auth.models import Permission
        
        # Critical permissions for each role
        role_permissions = {
            'Salesperson': [
                'view_all_deals', 'view_own_deals', 'create_deal', 'edit_deal', 'delete_deal', 'log_deal_activity',
                'view_all_clients', 'view_own_clients', 'create_new_client', 'edit_client_details', 'remove_client',
                'view_all_projects', 'view_own_projects', 'create_project', 'edit_project', 'delete_project',
                'view_all_teams', 'view_own_teams', 'create_new_team', 'edit_team_details', 'remove_team',
                'view_all_commissions', 'create_commission', 'edit_commission',
                'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
                'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
            ],
            'Verifier': [
                'view_payment_verification_dashboard', 'view_payment_analytics', 'view_audit_logs',
                'verify_deal_payment', 'verify_payments', 'manage_invoices', 'access_verification_queue', 'manage_refunds',
                'view_all_deals', 'view_own_deals', 'view_all_clients', 'view_own_clients',
                'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
                'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval'
            ]
        }
        
        for role_name, permission_codenames in role_permissions.items():
            if role_name in roles:
                org_role = roles[role_name]['organization']
                permissions = Permission.objects.filter(codename__in=permission_codenames)
                org_role.permissions.add(*permissions)
                self.stdout.write(self.style.SUCCESS(f"  ✅ Assigned {permissions.count()} permissions to {role_name}"))