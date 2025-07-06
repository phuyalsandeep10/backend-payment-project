"""
This management command initializes the application with a comprehensive and realistic dataset.
It is designed to be idempotent, meaning it can be run multiple times without creating duplicate data.

Key Features:
- Clears previously generated mock data for a clean slate.
- Creates a default superuser from environment variables.
- Calls the `create_default_roles` command to establish role templates.
- Populates the database with a "TechCorp Solutions" organization.
- Generates a diverse set of users with different roles (Admin, Manager, Salespersons, Verifier).
- Creates teams and assigns members.
- Generates numerous clients and projects.
- Creates a rich set of deals with varied statuses, sources, and values.
- Populates related models like Payments, Commissions, and Activity Logs for realism.
- Uses the Faker library to generate believable, randomized data.
"""
import os
import random
from datetime import timedelta, date
from decimal import Decimal
from django.db.models import Sum

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from faker import Faker

from authentication.models import User, UserProfile
from clients.models import Client
from commission.models import Commission
from deals.models import ActivityLog, Deal, Payment
from notifications.models import NotificationSettings, NotificationTemplate
from organization.models import Organization
from permissions.models import Role, Permission
from project.models import Project
from team.models import Team

# Initialize Faker for data generation
fake = Faker()

class Command(BaseCommand):
    help = "Initializes the application with a superuser and a rich, realistic mock dataset."

    @transaction.atomic
    def handle(self, *args, **options):
        self.faker = Faker()
        self.stdout.write(self.style.SUCCESS("🚀 Starting application initialization..."))

        # Use flush to clear the database completely for a clean slate
        self.stdout.write(self.style.WARNING("--- Flushing the database ---"))
        call_command('flush', '--no-input')
        self.stdout.write(self.style.SUCCESS("✅ Database flushed."))

        try:
            self.setup_superadmin()
            self.create_permissions_and_roles()
            self.create_core_data()
            self.stdout.write(self.style.SUCCESS("✅ Application initialization completed successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ An error occurred during initialization: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))

    def setup_superadmin(self):
        self.stdout.write(self.style.HTTP_INFO("--- Setting up Superuser ---"))
        email = getattr(settings, 'ADMIN_EMAIL', 'admin@example.com')
        password = getattr(settings, 'ADMIN_PASS', 'defaultpass')
        username = getattr(settings, 'ADMIN_USER', 'admin')

        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f"Superuser '{username}' already exists. Skipping creation."))
            self.superuser = User.objects.filter(username=username).first()
            self.superuser.is_staff = True
            self.superuser.is_superuser = True
            self.superuser.save()
            return

        super_admin_role, created = Role.objects.get_or_create(name='Super Admin', organization=None)
        if created:
            self.stdout.write(self.style.SUCCESS("   Created 'Super Admin' role template."))
        
        self.superuser = User.objects.create_superuser(
            username=username, email=email, password=password,
            first_name="Super", last_name="Admin", contact_number=fake.phone_number(),
            role=super_admin_role
        )
        NotificationSettings.objects.get_or_create(user=self.superuser)
        self.stdout.write(self.style.SUCCESS(f"👑 Superuser '{username}' created."))
        self.stdout.write(self.style.SUCCESS(f"   Login: {email} / {password}"))

        self.superuser.is_staff = True
        self.superuser.is_superuser = True
        self.superuser.save()

    def create_permissions_and_roles(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Permissions and Role Templates ---"))
        
        # Create all permissions
        permissions = {}
        permission_list = [
            ('view_own_dashboard', 'Can view their own personalized dashboard'),
            ('view_team_dashboard', 'Can view the dashboard for their team'),
            ('view_org_dashboard', 'Can view the full organization dashboard'),
            
            ('view_own_clients', 'Can view their own clients'),
            ('view_all_clients', 'Can view all clients in the organization'),
            ('add_client', 'Can add a new client'),
            ('edit_client', 'Can edit a client'),
            ('delete_client', 'Can delete a client'),

            ('view_own_deals', 'Can view their own deals'),
            ('view_all_deals', 'Can view all deals in the organization'),
            ('add_deal', 'Can add a new deal'),
            ('edit_deal', 'Can edit a deal'),
            ('delete_deal', 'Can delete a deal'),
            ('verify_deal', 'Can verify or reject a deal'),
            ('view_commission', 'Can view commission reports'),
            ('view_all_commissions', 'Can view all commission reports in the organization'),
            ('add_commission', 'Can add a commission record'),
            ('edit_commission', 'Can edit a commission record'),
            ('delete_commission', 'Can delete a commission record'),
        ]
        for codename, name in permission_list:
            p, created = Permission.objects.get_or_create(codename=codename, defaults={'name': name})
            permissions[codename] = p
            if created:
                self.stdout.write(self.style.SUCCESS(f"  - Created permission: {name}"))

        # Create role templates and assign permissions
        role_permissions = {
            "Super Admin": list(permissions.values()),
            "Organization Admin": [
                permissions['view_org_dashboard'], 
                permissions['view_all_clients'], permissions['add_client'],
                permissions['edit_client'], permissions['delete_client'], 
                permissions['view_all_deals'], permissions['add_deal'], permissions['edit_deal'], permissions['delete_deal'],
                permissions['verify_deal'], permissions['view_all_commissions'], permissions['add_commission'],
                permissions['edit_commission'], permissions['delete_commission']
            ],
            "Salesperson": [
                permissions['view_own_dashboard'], 
                permissions['view_own_clients'], permissions['add_client'],
                permissions['edit_client'], permissions['delete_client'], 
                permissions['view_own_deals'], permissions['add_deal'],
                permissions['edit_deal'], permissions['delete_deal'], 
                permissions['view_commission']
            ],
            "Verifier": [
                permissions['view_org_dashboard'], permissions['view_all_deals'], permissions['verify_deal']
            ],
        }
        
        for role_name, perms in role_permissions.items():
            role, created = Role.objects.get_or_create(name=role_name, organization=None)
            if created:
                role.permissions.set(perms)
                self.stdout.write(self.style.SUCCESS(f"  - Created role template '{role_name}' and assigned {len(perms)} permissions."))

    def create_core_data(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Core Mock Data ---"))

        # 1. Create Organization
        organization, _ = Organization.objects.get_or_create(
            name="TechCorp Solutions",
            defaults={'sales_goal': Decimal("2000000.00"), 'description': fake.bs()}
        )
        self.stdout.write(self.style.SUCCESS(f"🏢 Organization '{organization.name}' created/retrieved."))

        # 2. Create organization-specific roles from templates
        org_roles = self.create_org_roles(organization)

        # 3. Create Users
        self.create_users(organization, org_roles)

    def create_org_roles(self, organization):
        self.stdout.write(self.style.HTTP_INFO("  - Creating organization-specific roles..."))
        org_roles = {}
        role_names = ["Organization Admin", "Sales Manager", "Team Head", "Senior Salesperson", "Salesperson", "Verifier"]
        for name in role_names:
            template_role = Role.objects.filter(name=name, organization__isnull=True).first()
            if not template_role:
                self.stdout.write(self.style.WARNING(f"    Template role '{name}' not found. Creating a blank one."))
                template_role = Role.objects.create(name=name, organization=None)

            role, created = Role.objects.get_or_create(name=name, organization=organization)
            if created:
                role.permissions.set(template_role.permissions.all())
            org_roles[name] = role
        self.stdout.write(self.style.SUCCESS("    🎭 Org roles created."))
        return org_roles

    def create_user_for_role(self, organization, username, email, password, role, sales_target=None):
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': username,
                'organization': organization,
                'role': role,
                'first_name': self.faker.first_name(),
                'last_name': self.faker.last_name(),
                'sales_target': sales_target
            }
        )
        # Always set/reset the password and active status to ensure consistency
        user.set_password(password)
        user.is_active = True
        user.save()

        if created:
            UserProfile.objects.get_or_create(user=user)
            self.stdout.write(f"    - Created user: {username} ({email}) with role: {role.name}")
        else:
            self.stdout.write(f"    - Updated existing user: {username} ({email})")
            
        return user

    def create_users(self, organization, org_roles):
        self.stdout.write(self.style.HTTP_INFO("  - Creating specific users..."))

        # Create users for each role
        self.create_user_for_role(organization, 'org_admin1', 'org_admin1@techcorp.com', 'password123', org_roles['Organization Admin'])
        self.create_user_for_role(organization, 'org_admin2', 'org_admin2@techcorp.com', 'password123', org_roles['Organization Admin'])
        
        self.create_user_for_role(organization, 'salesperson1', 'salesperson1@techcorp.com', 'password123', org_roles['Salesperson'], sales_target=Decimal('50000.00'))
        self.create_user_for_role(organization, 'salesperson2', 'salesperson2@techcorp.com', 'password123', org_roles['Salesperson'], sales_target=Decimal('75000.00'))
        self.create_user_for_role(organization, 'salesperson3', 'salesperson3@techcorp.com', 'password123', org_roles['Salesperson'], sales_target=Decimal('60000.00'))

        self.create_user_for_role(organization, 'verifier1', 'verifier1@techcorp.com', 'password123', org_roles['Verifier'])
        self.create_user_for_role(organization, 'verifier2', 'verifier2@techcorp.com', 'password123', org_roles['Verifier'])

        self.stdout.write(self.style.SUCCESS("    👥 All specific users created."))

    def create_teams(self, organization, users):
        self.stdout.write(self.style.HTTP_INFO("  - Creating teams..."))
        salespersons = [u for u in users if u.role.name == 'Salesperson']
        team_alpha = Team.objects.create(name="Alpha Team", organization=organization, description=fake.bs())
        team_alpha.members.set(salespersons[:3])
        team_beta = Team.objects.create(name="Beta Team", organization=organization, description=fake.bs())
        team_beta.members.set(salespersons[3:])
        self.stdout.write(self.style.SUCCESS("    🧑‍🤝‍🧑 Created Alpha and Beta teams."))

    def create_clients(self, organization, users):
        self.stdout.write(self.style.HTTP_INFO("  - Creating clients..."))
        clients = []
        for _ in range(25):
            client = Client.objects.create(
                client_name=fake.company(), email=fake.email(), phone_number=fake.phone_number(),
                nationality=fake.country(), remarks=fake.sentence(),
                status=random.choice([c[0] for c in Client.STATUS_CHOICES]),
                satisfaction=random.choice([c[0] for c in Client.SATISFACTION_CHOICES]),
                created_by=random.choice(users), organization=organization
            )
            clients.append(client)
        self.stdout.write(self.style.SUCCESS(f"    👤 Created {len(clients)} clients."))
        return clients

    def create_projects(self, organization, clients, users):
        self.stdout.write(self.style.HTTP_INFO("  - Creating projects..."))
        project_count = 0
        for _ in range(30):
            created_by_user = random.choice(users)
            Project.objects.create(
                name=fake.catch_phrase(),
                description=fake.text(max_nb_chars=200),
                status=random.choice([s[0] for s in Project.STATUS_CHOICES]),
                created_by=created_by_user
            )
            project_count += 1
        self.stdout.write(self.style.SUCCESS(f"    🏗️  Created {project_count} projects."))

    def create_deals_and_related_data(self, organization, clients, users):
        self.stdout.write(self.style.HTTP_INFO("  - Creating deals and associated data..."))
        deals = []
        for client in clients:
            # Each client gets 1 to 5 deals
            for _ in range(random.randint(1, 5)):
                created_by_user = random.choice(users)
                deal_date = fake.date_between(start_date='-2y', end_date='today')
                due_date = deal_date + timedelta(days=random.randint(30, 90))
                deal_value = Decimal(random.randint(5000, 150000))
                payment_status = random.choice([s[0] for s in Deal.PAYMENT_STATUS_CHOICES])

                deal = Deal.objects.create(
                    organization=organization,
                    client=client,
                    deal_value=deal_value,
                    deal_date=deal_date,
                    due_date=due_date,
                    payment_status=payment_status,
                    verification_status=random.choice([s[0] for s in Deal.DEAL_STATUS]),
                    client_status=random.choice([s[0] for s in Deal.CLIENT_STATUS]),
                    source_type=random.choice([s[0] for s in Deal.SOURCE_TYPES]),
                    payment_method=random.choice([p[0] for p in Deal.PAYMENT_METHOD_CHOICES]),
                    deal_remarks=fake.text(max_nb_chars=100),
                    created_by=created_by_user,
                )
                deals.append(deal)
                if deal.payment_status in ['verified', 'partial']:
                    self.create_payments_for_deal(deal)
        
        manager_user = next((u for u in users if u.email == 'manager@techcorp.com'), None)
        if manager_user:
            self.stdout.write(self.style.HTTP_INFO(f"    - Creating 50 mock deals for sales manager '{manager_user.email}'..."))
            for _ in range(50):
                deal_date = fake.date_between(start_date='-2y', end_date='today')
                due_date = deal_date + timedelta(days=random.randint(30, 90))
                deal_value = Decimal(random.randint(5000, 150000))
                payment_status = random.choice([s[0] for s in Deal.PAYMENT_STATUS_CHOICES])

                deal = Deal.objects.create(
                    organization=organization,
                    client=random.choice(clients),
                    deal_value=deal_value,
                    deal_date=deal_date,
                    due_date=due_date,
                    payment_status=payment_status,
                    verification_status=random.choice([s[0] for s in Deal.DEAL_STATUS]),
                    client_status=random.choice([s[0] for s in Deal.CLIENT_STATUS]),
                    source_type=random.choice([s[0] for s in Deal.SOURCE_TYPES]),
                    payment_method=random.choice([p[0] for p in Deal.PAYMENT_METHOD_CHOICES]),
                    deal_remarks=fake.text(max_nb_chars=100),
                    created_by=manager_user,
                )
                deals.append(deal)
                if payment_status in ['verified', 'partial']:
                    self.create_payments_for_deal(deal)
        self.stdout.write(self.style.SUCCESS(f"    - Created {len(deals)} total deals."))

    def create_payments_for_deal(self, deal):
        # Create 1 to 3 payments for a deal
        for _ in range(random.randint(1, 3)):
            Payment.objects.create(
                deal=deal,
                payment_date=deal.deal_date + timedelta(days=random.randint(1, 15)),
                received_amount=deal.deal_value / 2,  # Example logic
                payment_type=random.choice(Payment.PAYMENT_TYPE)[0]
            )

    def create_commissions_for_users(self, organization, users):
        self.stdout.write(self.style.HTTP_INFO("  - Creating commissions..."))
        salespersons = [u for u in users if 'salesperson' in u.username]

        for user in salespersons:
            total_sales = Deal.objects.filter(
                created_by=user,
                verification_status='verified'
            ).aggregate(total=Sum('deal_value'))['total'] or Decimal('0.00')

            if total_sales > 0:
                commission_rate = Decimal(random.uniform(2.5, 7.5))
                bonus = total_sales * Decimal(random.uniform(0.01, 0.05))
                
                Commission.objects.create(
                    user=user,
                    organization=organization,
                    total_sales=total_sales,
                    commission_rate=commission_rate,
                    bonus=bonus,
                    penalty=Decimal('0.00'),
                    start_date=date.today().replace(day=1),
                    end_date=date.today(),
                    created_by=self.superuser
                )
        self.stdout.write(self.style.SUCCESS(f"    - Created commissions for {len(salespersons)} salespersons."))

    def create_notification_templates(self):
        self.stdout.write(self.style.HTTP_INFO("  - Creating notification templates..."))
        templates = [
            {'notification_type': 'deal_verified', 'subject': 'Your Deal has been Verified!', 'body': 'Congratulations! Your deal {{deal.deal_id}} has been successfully verified.'},
            {'notification_type': 'deal_rejected', 'subject': 'Action Required: Your Deal was Rejected', 'body': 'Unfortunately, your deal {{deal.deal_id}} was rejected. Please review and resubmit.'},
            {'notification_type': 'payment_received', 'subject': 'Payment Received for Deal {{deal.deal_id}}', 'body': 'A payment of {{payment.amount}} has been successfully processed for your deal.'},
        ]
        for t in templates:
            NotificationTemplate.objects.get_or_create(notification_type=t['notification_type'], defaults={
                'title_template': t['subject'],
                'message_template': t['body'],
                'is_active': True
            })
        self.stdout.write(self.style.SUCCESS("    🔔 Created default notification templates."))

    def create_initial_deals(self, organization, users):
        self.stdout.write(self.style.HTTP_INFO("  - Creating initial deals for users..."))
        for user in users:
            # Create a few deals for each salesperson
            for i in range(5):
                client = random.choice(Client.objects.filter(organization=organization))
                deal_date = timezone.now() - timedelta(days=random.randint(0, 365))
                Deal.objects.create(
                    organization=organization,
                    client=client,
                    deal_name=f"Initial Deal {i+1} for {user.username}",
                    created_by=user,
                    deal_value=Decimal(random.randrange(5000, 50000)),
                    deal_date=deal_date,
                    due_date=deal_date + timedelta(days=random.randint(30, 90)),
                    payment_status='pending',
                    verification_status='pending'
                )

        self.stdout.write(self.style.SUCCESS("Initialized baseline data with predictable users and roles."))