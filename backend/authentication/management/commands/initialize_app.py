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
from deals.models import Deal, Payment, PaymentApproval, PaymentInvoice
from organization.models import Organization
from permissions.models import Permission, Role
from project.models import Project

fake = Faker()

class Command(BaseCommand):
    help = "Initializes the application with a superuser and a rich, realistic mock dataset."

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🚀 Starting application initialization..."))

        # Using 'flush' is destructive but ensures a clean slate for development.
        self.stdout.write(self.style.WARNING("--- Flushing the database ---"))
        os.system('python manage.py flush --no-input')
        self.stdout.write(self.style.SUCCESS("✅ Database flushed."))

        try:
            self.create_permissions_and_roles()
            organization = self.create_organization()
            users = self.create_users(organization)
            clients = self.create_clients(organization, users)
            projects = self.create_projects(users)
            
            # Create a mix of historical and recent data
            self.create_deals_for_period(users, clients, projects, "historical", 60)
            self.create_deals_for_period(users, clients, projects, "recent", 15)
            
            # Create guaranteed consecutive deals for a specific user to build a streak
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
            # Client permissions
            {'name': 'View Client', 'codename': 'view_client', 'category': 'clients'},
            {'name': 'Add Client', 'codename': 'add_client', 'category': 'clients'},
            {'name': 'Edit Client', 'codename': 'edit_client', 'category': 'clients'},
            {'name': 'Delete Client', 'codename': 'delete_client', 'category': 'clients'},
            
            # Deal permissions
            {'name': 'View Deal', 'codename': 'view_deal', 'category': 'deals'},
            {'name': 'Add Deal', 'codename': 'add_deal', 'category': 'deals'},
            {'name': 'Edit Deal', 'codename': 'edit_deal', 'category': 'deals'},
            {'name': 'Delete Deal', 'codename': 'delete_deal', 'category': 'deals'},
            {'name': 'Verify Deal Payment', 'codename': 'verify_deal_payment', 'category': 'deals'},
            {'name': 'Log Deal Activity', 'codename': 'log_deal_activity', 'category': 'deals'},
            
            # Payment Invoice permissions
            {'name': 'View Payment Invoice', 'codename': 'view_paymentinvoice', 'category': 'deals'},
            {'name': 'Create Payment Invoice', 'codename': 'create_paymentinvoice', 'category': 'deals'},
            {'name': 'Edit Payment Invoice', 'codename': 'edit_paymentinvoice', 'category': 'deals'},
            {'name': 'Delete Payment Invoice', 'codename': 'delete_paymentinvoice', 'category': 'deals'},

            # Payment Approval permissions
            {'name': 'View Payment Approval', 'codename': 'view_paymentapproval', 'category': 'deals'},
            {'name': 'Create Payment Approval', 'codename': 'create_paymentapproval', 'category': 'deals'},
            {'name': 'Edit Payment Approval', 'codename': 'edit_paymentapproval', 'category': 'deals'},
            {'name': 'Delete Payment Approval', 'codename': 'delete_paymentapproval', 'category': 'deals'},

            # Project permissions
            {'name': 'View Project', 'codename': 'view_project', 'category': 'projects'},
            {'name': 'Add Project', 'codename': 'add_project', 'category': 'projects'},
            
            # Verifier Dashboard Permissions
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
            Permission.objects.get_or_create(
                codename=perm_data['codename'],
                defaults={'name': perm_data['name'], 'category': perm_data['category']}
            )
        self.stdout.write(self.style.SUCCESS(f"✅ Created/verified {len(permissions_data)} permissions."))

        self.stdout.write(self.style.HTTP_INFO("--- Creating Role Templates and Assigning Permissions ---"))
        role_permissions = self.get_role_permissions()
        for role_name, perms in role_permissions.items():
            role, _ = Role.objects.get_or_create(name=role_name, organization=None)
            permissions = Permission.objects.filter(codename__in=perms)
            role.permissions.set(permissions)
            self.stdout.write(self.style.SUCCESS(f"  - Created role template '{role_name}' and assigned {len(perms)} permissions."))

    def create_organization(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Organization ---"))
        organization, _ = Organization.objects.get_or_create(
            name="Innovate Inc.",
            defaults={'sales_goal': Decimal("3000000.00"), 'description': fake.bs()}
        )
        self.stdout.write(self.style.SUCCESS(f"🏢 Organization '{organization.name}' created."))
        return organization

    def create_users(self, organization):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Users and Roles ---"))
        users = {}
        
        # Create Org-Specific Roles and Users
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
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        'username': username, 'organization': organization, 'role': org_role,
                        'first_name': fake.first_name(), 'last_name': fake.last_name(),
                        'sales_target': Decimal(random.randint(50000, 150000)) if role_name == "Salesperson" else None
                    }
                )
                user.set_password("password123")
                user.is_active = True
                if role_name == "Super Admin":
                    user.is_superuser = True
                    user.is_staff = True
                user.save()
                users[username] = user
                
        self.stdout.write(self.style.SUCCESS("👥 Users and roles created."))
        return users

    def create_clients(self, organization, users):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Clients ---"))
        clients = []
        sales_users = [u for u in users.values() if u.role.name == 'Salesperson']
        for _ in range(25):
            clients.append(Client.objects.create(
                organization=organization, client_name=fake.company(),
                email=fake.unique.email(), phone_number=fake.phone_number(),
                created_by=random.choice(sales_users)
            ))
        self.stdout.write(self.style.SUCCESS(f"👤 Created {len(clients)} clients."))
        return clients

    def create_projects(self, users):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Projects ---"))
        projects = []
        for _ in range(10):
            projects.append(Project.objects.create(
                name=fake.catch_phrase(), description=fake.text(),
                created_by=random.choice(list(users.values()))
            ))
        self.stdout.write(self.style.SUCCESS(f"🏗️ Created {len(projects)} projects."))
        return projects

    def create_deals_for_period(self, users, clients, projects, period, count):
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating {period.capitalize()} Deals ---"))
        salespersons = [u for u in users.values() if u.role.name == 'Salesperson']
        verifiers = [u for u in users.values() if u.role.name == 'Verifier']

        for _ in range(count):
            now = timezone.now()
            if period == "recent":
                # Deals within the current month
                deal_date = now.date() - timedelta(days=random.randint(0, now.day - 1 if now.day > 1 else 0))
            else: # historical
                deal_date = fake.date_between(start_date='-2y', end_date='-1M')

            deal = Deal.objects.create(
                organization=users['orgadmin'].organization,
                client=random.choice(clients),
                project=random.choice(projects) if projects and random.random() > 0.5 else None,
                deal_name=fake.bs().title(),
                deal_value=Decimal(random.randint(10000, 95000)),
                deal_date=deal_date,
                payment_method=random.choice([c[0] for c in Deal.PAYMENT_METHOD_CHOICES]),
                source_type=random.choice([c[0] for c in Deal.SOURCE_TYPES]),
                created_by=random.choice(salespersons)
            )

            # 80% of deals get a payment and verification
            if random.random() < 0.8 and verifiers:
                self.process_deal_payment_and_verification(deal, verifiers)

    def process_deal_payment_and_verification(self, deal, verifiers):
        # A payment is made 1-10 days after the deal
        payment_date = deal.deal_date + timedelta(days=random.randint(1, 10))
        received_amount = deal.deal_value * Decimal(random.uniform(0.5, 1.0))
        payment = Payment.objects.create(
            deal=deal,
            received_amount=received_amount.quantize(Decimal('0.01')),
            payment_date=payment_date,
            payment_type=deal.payment_method
        )
        
        # Signal creates PaymentInvoice automatically
        invoice = PaymentInvoice.objects.get(payment=payment) 

        # Verification happens 1-5 days after payment
        verifier = random.choice(verifiers)
        is_verified = random.random() < 0.9 # 90% are verified

        if is_verified:
            invoice.invoice_status = 'verified'
            deal.verification_status = 'verified'
            deal.payment_status = 'full_payment' if payment.received_amount == deal.deal_value else 'initial payment'
            action = "Verified"
            
            # Create a commission record for the salesperson
            if deal.created_by.role and deal.created_by.role.name == 'Salesperson':
                start_of_month = deal.deal_date.replace(day=1)
                end_of_month = start_of_month + timedelta(days=32)
                end_of_month = end_of_month.replace(day=1) - timedelta(days=1)
                
                Commission.objects.create(
                    user=deal.created_by,
                    organization=deal.organization,
                    total_sales=deal.deal_value,
                    commission_rate=Decimal(random.uniform(3.0, 8.0)),
                    start_date=start_of_month,
                    end_date=end_of_month,
                    created_by=verifier
                )
        else:
            invoice.invoice_status = 'rejected'
            deal.verification_status = 'rejected'
            action = "Rejected"
        
        invoice.save()
        deal.save()
        
        PaymentApproval.objects.create(
            deal=deal, payment=payment, approved_by=verifier,
            approved_remarks=f"This invoice was {action.lower()}."
        )
        AuditLogs.objects.create(
            organization=deal.organization, user=verifier, action=action,
            details=f"Invoice {invoice.invoice_id} for deal {deal.deal_id} was {action.lower()}."
        )

    def create_streak_building_deals(self, salesperson, clients, projects, verifiers):
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating Streak-Building Deals for {salesperson.username} ---"))
        now = timezone.now()
        # Create 5 verified deals on consecutive days leading up to today
        for i in range(5):
            deal_date = now.date() - timedelta(days=i)
            
            deal = Deal.objects.create(
                organization=salesperson.organization,
                client=random.choice(clients),
                project=random.choice(projects) if projects and random.random() > 0.5 else None,
                deal_name=f"Streak Deal Day {5-i}",
                deal_value=Decimal(random.randint(200, 5000)), # Ensure value > 101
                deal_date=deal_date,
                payment_method=random.choice([c[0] for c in Deal.PAYMENT_METHOD_CHOICES]),
                source_type='referral',
                created_by=salesperson,
            )

            # This part MUST succeed to build a streak
            payment_date = deal.deal_date + timedelta(days=random.randint(0, 1))
            received_amount = deal.deal_value * Decimal(random.uniform(0.6, 1.0))
            payment = Payment.objects.create(
                deal=deal,
                received_amount=received_amount.quantize(Decimal('0.01')),
                payment_date=payment_date,
                payment_type=deal.payment_method
            )
            
            invoice = PaymentInvoice.objects.get(payment=payment)
            verifier = random.choice(verifiers)

            # Guarantee verification
            invoice.invoice_status = 'verified'
            deal.verification_status = 'verified'
            deal.payment_status = 'full_payment' if received_amount == deal.deal_value else 'initial payment'
            action = "Verified"
            
            invoice.save()
            deal.save()
            
            PaymentApproval.objects.create(
                deal=deal, payment=payment, approved_by=verifier,
                approved_remarks=f"Invoice automatically {action.lower()} by system."
            )
            
            AuditLogs.objects.create(
                organization=deal.organization, user=verifier, action=action,
                details=f"Invoice {invoice.invoice_id} for deal {deal.deal_id} was {action.lower()}."
            )
        self.stdout.write(self.style.SUCCESS(f"✅ Created 5 consecutive daily deals to build a streak."))

    def get_role_permissions(self):
        # Define all permissions required by the app
        return {
            "Super Admin": [
                'view_deal', 'add_deal', 'edit_deal', 'delete_deal', 
                'view_client', 'add_client', 'edit_client', 'delete_client', 
                'view_payment_verification_dashboard', 'can_verify_payment', 'view_paymentinvoice'
            ],
            "Organization Admin": [
                'view_deal', 'add_deal', 'edit_deal', 'delete_deal',
                'view_client', 'add_client', 'edit_client', 'delete_client'
            ],
            "Salesperson": [
                'view_deal', 'add_deal', 'edit_deal',
                'view_client', 'add_client', 'edit_client',
                'view_project', 'add_project',
                'view_dashboard',
                'view_own_performance',
                'view_own_commission'
            ],
            "Verifier": [
                'view_payment_verification_dashboard',
                'view_payment_analytics',
                'manage_invoices',
                'access_verification_queue',
                'verify_payments',
                'reject_payments',
                'manage_refunds',
                'view_audit_logs',
                'view_deal',
                'view_paymentinvoice',
                'view_client',
                'view_project'
            ]
        } 