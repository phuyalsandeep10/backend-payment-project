import os
import random
from datetime import date, timedelta
from decimal import Decimal

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction

from authentication.models import User
from clients.models import Client
from deals.models import Deal
from organization.models import Organization
from permissions.models import Role


class Command(BaseCommand):
    help = "Initializes the application with a superuser and mock data. This command is intended to be run once."

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting application initialization..."))

        # Check if the app is already initialized by looking for a superuser
        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write(self.style.WARNING("Application appears to be already initialized. A superuser exists."))
            self.stdout.write(self.style.NOTICE("Skipping initialization."))
            return

        self.stdout.write(self.style.NOTICE("No superuser found. Proceeding with initialization."))

        try:
            self.setup_superadmin()
            self.create_mock_data()
            self.stdout.write(self.style.SUCCESS("Application initialization completed successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"An error occurred during initialization: {e}"))
            # The transaction will be rolled back.

    def setup_superadmin(self):
        self.stdout.write(self.style.HTTP_INFO("--- Setting up Superuser ---"))
        admin_email = getattr(settings, 'ADMIN_EMAIL', 'admin@example.com')
        admin_password = getattr(settings, 'ADMIN_PASS', 'defaultpass')
        admin_username = getattr(settings, 'ADMIN_USER', 'admin')

        if User.objects.filter(email=admin_email).exists():
            self.stdout.write(self.style.WARNING(f"Superuser with email {admin_email} already exists. Skipping creation."))
            return

        super_admin_role, _ = Role.objects.get_or_create(name='Super Admin', organization=None)

        User.objects.create_superuser(
            username=admin_username,
            email=admin_email,
            password=admin_password,
            role=super_admin_role
        )
        self.stdout.write(self.style.SUCCESS(f"Superuser '{admin_username}' created successfully."))

    def create_mock_data(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Mock Data ---"))

        # 1. Create Organization
        org_name = "Innovate Corp"
        if Organization.objects.filter(name=org_name).exists():
            organization = Organization.objects.get(name=org_name)
            self.stdout.write(self.style.WARNING(f"Organization '{org_name}' already exists. Skipping creation."))
        else:
            organization = Organization.objects.create(name=org_name, sales_goal=Decimal("500000.00"))
            self.stdout.write(self.style.SUCCESS(f"Organization '{org_name}' created."))

        # 2. Create Roles for the organization
        org_admin_role, _ = Role.objects.get_or_create(name='Organization Admin', organization=organization)
        salesperson_role, _ = Role.objects.get_or_create(name='Salesperson', organization=organization)

        # 3. Create an Organization Admin
        org_admin_email = "org.admin@innovate.com"
        if not User.objects.filter(email=org_admin_email).exists():
            User.objects.create_user(
                username='org.admin',
                email=org_admin_email,
                password='password123',
                role=org_admin_role,
                organization=organization,
                is_staff=True  # Org admins should probably have staff access
            )
            self.stdout.write(self.style.SUCCESS(f"Organization Admin '{org_admin_email}' created."))
        else:
            self.stdout.write(self.style.WARNING(f"User '{org_admin_email}' already exists. Skipping creation."))


        # 4. Create a Salesperson
        salesperson_email = "sales.person@innovate.com"
        if not User.objects.filter(email=salesperson_email).exists():
            salesperson = User.objects.create_user(
                username='sales.person',
                email=salesperson_email,
                password='password123',
                role=salesperson_role,
                organization=organization
            )
            self.stdout.write(self.style.SUCCESS(f"Salesperson '{salesperson_email}' created."))
        else:
            salesperson = User.objects.get(email=salesperson_email)
            self.stdout.write(self.style.WARNING(f"User '{salesperson_email}' already exists. Skipping creation."))


        # 5. Create Clients for the Salesperson
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating Mock Clients for {salesperson.email} ---"))
        clients_to_create = [
            {'client_name': 'Tech Solutions Ltd.', 'email': 'contact@techsolutions.com', 'phone_number': '111222333'},
            {'client_name': 'Global Exports Inc.', 'email': 'info@globalexports.com', 'phone_number': '444555666'},
            {'client_name': 'Green Innovations', 'email': 'hello@greeninnovations.com', 'phone_number': '777888999'},
        ]

        clients_created_count = 0
        for client_data in clients_to_create:
            if not Client.objects.filter(email=client_data['email'], organization=organization).exists():
                Client.objects.create(
                    client_name=client_data['client_name'],
                    email=client_data['email'],
                    phone_number=client_data['phone_number'],
                    organization=organization,
                    created_by=salesperson
                )
                clients_created_count += 1
                self.stdout.write(self.style.SUCCESS(f"Client '{client_data['client_name']}' created."))
        
        if clients_created_count == 0:
            self.stdout.write(self.style.WARNING("All mock clients already exist. Skipping client creation."))
        else:
            self.stdout.write(f"{clients_created_count} clients created.")


        # 6. Create Deals for the clients
        self.stdout.write(self.style.HTTP_INFO(f"--- Creating Mock Deals for {salesperson.email} ---"))
        clients = Client.objects.filter(created_by=salesperson)
        deals_created_count = 0
        for client in clients:
            if not Deal.objects.filter(created_by=salesperson, client_name=client.client_name).exists():
                for _ in range(random.randint(1, 3)): # Create 1 to 3 deals per client
                    deal_date = date.today() - timedelta(days=random.randint(0, 90))
                    Deal.objects.create(
                        client_name=client.client_name,
                        deal_value=Decimal(random.randrange(5000, 100000)),
                        deal_date=deal_date,
                        due_date=deal_date + timedelta(days=random.randint(15, 60)),
                        deal_status=random.choice(['pending', 'won', 'lost']),
                        pay_status=random.choice(['pending', 'partial', 'verified']),
                        created_by=salesperson,
                        organization=salesperson.organization
                    )
                    deals_created_count += 1
                self.stdout.write(self.style.SUCCESS(f"Deals created for client '{client.client_name}'."))

        if deals_created_count == 0:
            self.stdout.write(self.style.WARNING("Mock deals seem to exist for this salesperson. Skipping deal creation."))
        else:
             self.stdout.write(f"{deals_created_count} deals created.") 