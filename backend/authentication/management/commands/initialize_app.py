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
from permissions.models import Role
from project.models import Project
from team.models import Team

# Initialize Faker for data generation
fake = Faker()

class Command(BaseCommand):
    help = "Initializes the application with a superuser and a rich, realistic mock dataset."

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🚀 Starting application initialization..."))

        try:
            self.clear_mock_data()
            self.setup_superadmin()
            self.create_mock_data()
            self.stdout.write(self.style.SUCCESS("✅ Application initialization completed successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ An error occurred during initialization: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))

    def clear_mock_data(self):
        self.stdout.write(self.style.WARNING("--- Clearing existing mock data for 'TechCorp Solutions' ---"))
        org_to_delete = Organization.objects.filter(name="TechCorp Solutions").first()
        if not org_to_delete:
            self.stdout.write(self.style.HTTP_INFO("No existing 'TechCorp Solutions' mock data to clear."))
            return

        # Deletion order is critical to avoid foreign key constraint violations
        models_to_delete = [
            Payment, ActivityLog, Commission, Deal, Project, Team, Client,
            NotificationSettings, UserProfile
        ]
        for model in models_to_delete:
            # Assumes a link to organization, direct or indirect, for deletion filtering
            # This is a simplification; direct relations are required for this to work perfectly.
            # Example: Payment -> Deal -> Organization
            app_label = model._meta.app_label
            model_name = model._meta.model_name
            qs = model.objects.all()
            
            if hasattr(model, 'deal') and hasattr(model.deal.field.related_model, 'organization'):
                qs = model.objects.filter(deal__organization=org_to_delete)
            elif hasattr(model, 'organization'):
                qs = model.objects.filter(organization=org_to_delete)
            elif hasattr(model, 'user') and hasattr(model.user.field.related_model, 'organization'):
                qs = model.objects.filter(user__organization=org_to_delete)

            count = qs.count()
            if count > 0:
                qs.delete()
                self.stdout.write(self.style.SUCCESS(f"  - Deleted {count} {model_name} records from {app_label}"))

        # Delete users and roles associated with the organization
        User.objects.filter(organization=org_to_delete, is_superuser=False).delete()
        self.stdout.write(self.style.SUCCESS("  - Deleted users for TechCorp Solutions"))
        Role.objects.filter(organization=org_to_delete).delete()
        self.stdout.write(self.style.SUCCESS("  - Deleted roles for TechCorp Solutions"))
        org_to_delete.delete()
        self.stdout.write(self.style.SUCCESS("✅ Cleared mock data for 'TechCorp Solutions'."))

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

    def create_mock_data(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Realistic Mock Data ---"))

        # 1. Create Notification Templates FIRST
        self.create_notification_templates()

        # 2. Create Organization
        organization, _ = Organization.objects.get_or_create(
            name="TechCorp Solutions",
            defaults={'sales_goal': Decimal("2000000.00"), 'description': fake.bs()}
        )
        self.stdout.write(self.style.SUCCESS(f"🏢 Organization '{organization.name}' created/retrieved."))

        # 3. Create organization-specific roles
        org_roles = self.create_org_roles(organization)

        # 4. Create Users
        users = self.create_users(organization, org_roles)

        # 5. Create Teams
        self.create_teams(organization, users)

        # 6. Create Clients
        clients = self.create_clients(organization, users)

        # 7. Create Projects
        self.create_projects(organization, clients, users)

        # 8. Create Deals and associated data
        self.create_deals_and_related_data(organization, clients, users)
        self.create_commissions_for_users(organization, users)

        self.stdout.write(self.style.SUCCESS("✅ Realistic mock data created successfully!"))

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

    def create_users(self, organization, org_roles):
        self.stdout.write(self.style.HTTP_INFO("  - Creating users..."))
        users = {}
        user_data = [
            {'key': 'admin', 'username': 'orgadmin', 'email': 'admin@techcorp.com', 'role': 'Organization Admin', 'is_staff': True},
            {'key': 'manager', 'username': 'salesmanager', 'email': 'manager@techcorp.com', 'role': 'Sales Manager'},
            {'key': 'verifier', 'username': 'verifier', 'email': 'verifier@techcorp.com', 'role': 'Verifier'},
            {'key': 'salesperson', 'username': 'salesperson', 'email': 'sales@techcorp.com', 'role': 'Salesperson'},
        ]
        for i in range(5):
            user_data.append({'key': f'sales_{i}', 'username': fake.user_name(), 'email': fake.email(), 'role': 'Salesperson'})

        for data in user_data:
            user = User.objects.filter(username=data['username']).first()
            if not user:
                user = User.objects.create_user(
                    username=data['username'], email=data['email'], password='password123',
                    first_name=fake.first_name(), last_name=fake.last_name(),
                    contact_number=fake.phone_number(), organization=organization,
                    role=org_roles[data['role']], is_staff=data.get('is_staff', False),
                    sales_target=Decimal(random.randint(50000, 150000))
                )
            
            # Ensure UserProfile and NotificationSettings are created only if they don't exist
            UserProfile.objects.get_or_create(user=user, defaults={'bio': fake.text(max_nb_chars=150)})
            NotificationSettings.objects.get_or_create(user=user)
            
            users[data['key']] = user
        self.stdout.write(self.style.SUCCESS(f"    👥 Created/retrieved {len(users)} users."))
        return list(users.values())

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
        self.stdout.write(self.style.HTTP_INFO("  - Creating commissions for users..."))
        commission_count = 0
        for user in users:
            # Aggregate total sales for each user
            total_sales = Deal.objects.filter(
                created_by=user,
                organization=organization
            ).aggregate(total=Sum('deal_value'))['total'] or Decimal('0.00')

            if total_sales > 0:
                Commission.objects.create(
                    organization=organization,
                    user=user,
                    total_sales=total_sales,
                    start_date=date(2024, 1, 1),
                    end_date=date(2024, 12, 31),
                    created_by=self.superuser
                )
                commission_count += 1
        self.stdout.write(self.style.SUCCESS(f"    💸 Created {commission_count} commission records."))

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