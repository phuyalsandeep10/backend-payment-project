import os
import random
from datetime import timedelta
from decimal import Decimal

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from faker import Faker

from Verifier_dashboard.models import AuditLogs
from authentication.models import User
from clients.models import Client
from commission.models import Commission
from deals.models import Deal, Payment, PaymentApproval, PaymentInvoice, ActivityLog
from notifications.models import Notification, NotificationSettings
from organization.models import Organization
from permissions.models import Permission, Role
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

        try:
            permissions_data = self.create_permissions_and_roles()
            organization = self.create_organization()
            users = self.create_users(organization, permissions_data)
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

    def create_permissions_and_roles(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Custom Permissions ---"))
        permissions_data = [
            {'name': 'View Client', 'codename': 'view_client', 'category': 'clients'},
            {'name': 'Add Client', 'codename': 'add_client', 'category': 'clients'},
            {'name': 'Edit Client', 'codename': 'edit_client', 'category': 'clients'},
            {'name': 'Delete Client', 'codename': 'delete_client', 'category': 'clients'},
            {'name': 'View Deal', 'codename': 'view_deal', 'category': 'deals'},
            {'name': 'Add Deal', 'codename': 'add_deal', 'category': 'deals'},
            {'name': 'Edit Deal', 'codename': 'edit_deal', 'category': 'deals'},
            {'name': 'Delete Deal', 'codename': 'delete_deal', 'category': 'deals'},
            {'name': 'Verify Deal Payment', 'codename': 'verify_deal_payment', 'category': 'deals'},
            {'name': 'Log Deal Activity', 'codename': 'log_deal_activity', 'category': 'deals'},
            {'name': 'View Payment Invoice', 'codename': 'view_paymentinvoice', 'category': 'deals'},
            {'name': 'Create Payment Invoice', 'codename': 'create_paymentinvoice', 'category': 'deals'},
            {'name': 'Edit Payment Invoice', 'codename': 'edit_paymentinvoice', 'category': 'deals'},
            {'name': 'Delete Payment Invoice', 'codename': 'delete_paymentinvoice', 'category': 'deals'},
            {'name': 'View Payment Approval', 'codename': 'view_paymentapproval', 'category': 'deals'},
            {'name': 'Create Payment Approval', 'codename': 'create_paymentapproval', 'category': 'deals'},
            {'name': 'Edit Payment Approval', 'codename': 'edit_paymentapproval', 'category': 'deals'},
            {'name': 'Delete Payment Approval', 'codename': 'delete_paymentapproval', 'category': 'deals'},
            {'name': 'View Project', 'codename': 'view_project', 'category': 'projects'},
            {'name': 'Add Project', 'codename': 'add_project', 'category': 'projects'},
            {'name': 'View Verifier Dashboard', 'codename': 'view_payment_verification_dashboard', 'category': 'verifier_dashboard'},
            {'name': 'Can Verify Payment', 'codename': 'can_verify_payment', 'category': 'verifier_dashboard'},
            {'name': 'View Payment Analytics', 'codename': 'view_payment_analytics', 'category': 'verifier_dashboard'},
            {'name': 'Manage Invoices', 'codename': 'manage_invoices', 'category': 'verifier_dashboard'},
            {'name': 'Access Verification Queue', 'codename': 'access_verification_queue', 'category': 'verifier_dashboard'},
            {'name': 'Verify Payments', 'codename': 'verify_payments', 'category': 'verifier_dashboard'},
            {'name': 'Reject Payments', 'codename': 'reject_payments', 'category': 'verifier_dashboard'},
            {'name': 'Manage Refunds', 'codename': 'manage_refunds', 'category': 'verifier_dashboard'},
            {'name': 'View Audit Logs', 'codename': 'view_audit_logs', 'category': 'verifier_dashboard'},
        ]
        for perm_data in permissions_data:
            Permission.objects.get_or_create(codename=perm_data['codename'], defaults={'name': perm_data['name'], 'category': perm_data['category']})
        self.stdout.write(self.style.SUCCESS(f"✅ Created/verified {len(permissions_data)} permissions."))
        return permissions_data

    def create_organization(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Organization ---"))
        organization, _ = Organization.objects.get_or_create(name="Innovate Inc.", defaults={'sales_goal': Decimal("500000.00"), 'description': fake.bs()})
        self.stdout.write(self.style.SUCCESS(f"🏢 Organization '{organization.name}' created."))
        return organization

    def create_users(self, organization, permissions_data):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Users and Roles ---"))
        role_permissions = self.get_role_permissions(permissions_data)
        for role_name, perms in role_permissions.items():
            role, _ = Role.objects.get_or_create(name=role_name, organization=None)
            permissions = Permission.objects.filter(codename__in=perms)
            role.permissions.set(permissions)
            self.stdout.write(self.style.SUCCESS(f"  - Created role template '{role_name}' and assigned {len(perms)} permissions."))
        
        users = {}
        user_data = {
            "Super Admin": [("superadmin", "super@innovate.com")],
            "Organization Admin": [("orgadmin", "admin@innovate.com")],
            "Salesperson": [("salestest", "sales@innovate.com"), ("salespro", "salespro@innovate.com")],
            "Verifier": [("verifier", "verifier@innovate.com")],
        }
        for role_name, user_list in user_data.items():
            org_role, _ = Role.objects.get_or_create(name=role_name, organization=organization)
            template_role = Role.objects.get(name=role_name, organization__isnull=True)
            org_role.permissions.set(template_role.permissions.all())
            for username, email in user_list:
                user, created = User.objects.get_or_create(email=email, defaults={'username': username, 'organization': organization, 'role': org_role, 'first_name': fake.first_name(), 'last_name': fake.last_name(), 'sales_target': Decimal(random.randint(25000, 75000)) if role_name == "Salesperson" else None})
                user.set_password("password123")
                user.is_active = True
                if role_name == "Super Admin":
                    user.is_superuser = True
                    user.is_staff = True
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
            deal_date = today - timedelta(days=i)
            deal = Deal.objects.create(organization=salesperson.organization, client=random.choice(clients), project=random.choice(projects) if projects and random.random() > 0.5 else None, deal_name=f"Streak Deal Day {i+1}", deal_value=Decimal(random.randint(500, 2000)), deal_date=deal_date, payment_method='bank', source_type='referral', created_by=salesperson, payment_status='initial payment')
            self.create_payment_flow(deal, deal.deal_value, deal_date, random.choice(verifiers), 'verified_full')

    def get_role_permissions(self, permissions_data):
        sales_perms = ['view_client', 'add_client', 'edit_client', 'view_deal', 'add_deal', 'edit_deal', 'delete_deal', 'log_deal_activity', 'view_project', 'add_project']
        verifier_perms = [
            'view_payment_verification_dashboard',
            'can_verify_payment',
            'view_payment_analytics',
            'manage_invoices',
            'access_verification_queue',
            'verify_payments',
            'reject_payments',
            'manage_refunds',
            'view_audit_logs',
            'view_deal',
            'view_client',
            'view_project',
            'verify_deal_payment',
            'view_paymentinvoice', 'create_paymentinvoice', 'edit_paymentinvoice', 'delete_paymentinvoice',
            'view_paymentapproval', 'create_paymentapproval', 'edit_paymentapproval', 'delete_paymentapproval',
        ]
        admin_perms = sales_perms + verifier_perms + ['delete_client']
        return {
            "Super Admin": [p['codename'] for p in permissions_data],
            "Organization Admin": admin_perms,
            "Salesperson": sales_perms,
            "Verifier": verifier_perms,
        }