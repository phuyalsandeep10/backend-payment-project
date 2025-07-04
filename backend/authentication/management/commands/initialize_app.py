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

        try:
            super_admin_role, _ = Role.objects.get_or_create(name='Super Admin', organization=None)

            # Create superuser with explicit password setting
            superuser = User.objects.create_superuser(
                username=admin_username,
                email=admin_email,
                password=admin_password,
                role=super_admin_role
            )
            
            # Ensure the password is set correctly and user is active
            superuser.set_password(admin_password)
            superuser.is_active = True
            superuser.is_staff = True
            superuser.is_superuser = True
            superuser.save()
            
            self.stdout.write(self.style.SUCCESS(f"Superuser '{admin_username}' created successfully."))
            self.stdout.write(self.style.SUCCESS(f"✅ Login credentials: {admin_email} / {admin_password}"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error creating superuser: {e}"))
            # Continue anyway - don't let errors stop the process
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))

    def create_mock_data(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Realistic Mock Data Following Business Flow ---"))

        # 1. Super Admin creates Organization
        org_name = "TechCorp Solutions"
        if Organization.objects.filter(name=org_name).exists():
            organization = Organization.objects.get(name=org_name)
            self.stdout.write(self.style.WARNING(f"Organization '{org_name}' already exists. Using existing."))
        else:
            organization = Organization.objects.create(
                name=org_name, 
                sales_goal=Decimal("1500000.00")  # 1.5M annual sales goal
            )
            self.stdout.write(self.style.SUCCESS(f"📊 Organization '{org_name}' created by Super Admin."))

        # 2. Super Admin creates Roles for the organization
        org_admin_role, _ = Role.objects.get_or_create(name='Organization Admin', organization=organization)
        sales_manager_role, _ = Role.objects.get_or_create(name='Sales Manager', organization=organization)
        senior_salesperson_role, _ = Role.objects.get_or_create(name='Senior Salesperson', organization=organization)
        salesperson_role, _ = Role.objects.get_or_create(name='Salesperson', organization=organization)
        
        self.stdout.write(self.style.SUCCESS("🎭 Roles created: Org Admin, Sales Manager, Senior Salesperson, Salesperson"))

        # 3. Super Admin assigns Organization Admin
        org_admin_email = "admin@techcorp.com"
        org_admin_password = "admin123"
        if not User.objects.filter(email=org_admin_email).exists():
            org_admin = User.objects.create_user(
                username='orgadmin',
                email=org_admin_email,
                password=org_admin_password,
                role=org_admin_role,
                organization=organization,
                is_staff=True
            )
            org_admin.set_password(org_admin_password)
            org_admin.is_active = True
            org_admin.save()
            self.stdout.write(self.style.SUCCESS(f"👑 Organization Admin '{org_admin_email}' assigned by Super Admin."))
            self.stdout.write(self.style.SUCCESS(f"✅ Login: {org_admin_email} / {org_admin_password}"))
        else:
            org_admin = User.objects.get(email=org_admin_email)
            self.stdout.write(self.style.WARNING(f"Org Admin '{org_admin_email}' already exists."))

        # 4. Org Admin creates Sales Manager
        sales_manager_email = "manager@techcorp.com"
        sales_manager_password = "manager123"
        if not User.objects.filter(email=sales_manager_email).exists():
            sales_manager = User.objects.create_user(
                username='salesmanager',
                email=sales_manager_email,
                password=sales_manager_password,
                role=sales_manager_role,
                organization=organization,
                sales_target=Decimal("500000.00")
            )
            sales_manager.set_password(sales_manager_password)
            sales_manager.is_active = True
            sales_manager.save()
            self.stdout.write(self.style.SUCCESS(f"🎯 Sales Manager '{sales_manager_email}' created by Org Admin."))
            self.stdout.write(self.style.SUCCESS(f"✅ Login: {sales_manager_email} / {sales_manager_password}"))
        else:
            sales_manager = User.objects.get(email=sales_manager_email)

        # 5. Org Admin creates 3 Salesperson users
        salesperson_data = [
            {
                'username': 'john.smith',
                'email': 'john.smith@techcorp.com',
                'password': 'john123',
                'role': senior_salesperson_role,
                'target': Decimal("300000.00"),
                'name': 'John Smith'
            },
            {
                'username': 'sarah.johnson',
                'email': 'sarah.johnson@techcorp.com',
                'password': 'sarah123',
                'role': salesperson_role,
                'target': Decimal("200000.00"),
                'name': 'Sarah Johnson'
            },
            {
                'username': 'mike.davis',
                'email': 'mike.davis@techcorp.com',
                'password': 'mike123',
                'role': salesperson_role,
                'target': Decimal("250000.00"),
                'name': 'Mike Davis'
            }
        ]

        salespeople = []
        for sp_data in salesperson_data:
            if not User.objects.filter(email=sp_data['email']).exists():
                salesperson = User.objects.create_user(
                    username=sp_data['username'],
                    email=sp_data['email'],
                    password=sp_data['password'],
                    role=sp_data['role'],
                    organization=organization,
                    sales_target=sp_data['target']
                )
                salesperson.set_password(sp_data['password'])
                salesperson.is_active = True
                salesperson.save()
                salespeople.append(salesperson)
                self.stdout.write(self.style.SUCCESS(f"👤 {sp_data['name']} ({sp_data['role'].name}) created by Org Admin."))
                self.stdout.write(self.style.SUCCESS(f"✅ Login: {sp_data['email']} / {sp_data['password']}"))
            else:
                salespeople.append(User.objects.get(email=sp_data['email']))

        # 6. Create realistic clients for each salesperson (20+ each)
        self.stdout.write(self.style.HTTP_INFO("--- Creating Diverse Client Portfolio ---"))
        
        # Client templates with varied industries and sizes
        client_templates = [
            # Tech Sector
            {'name': 'InnovateTech Solutions', 'email': 'contact@innovatetech.com', 'phone': '+1-555-0101', 'industry': 'Technology'},
            {'name': 'CloudFirst Systems', 'email': 'info@cloudfirst.com', 'phone': '+1-555-0102', 'industry': 'Technology'},
            {'name': 'DataStream Analytics', 'email': 'hello@datastream.com', 'phone': '+1-555-0103', 'industry': 'Technology'},
            {'name': 'CyberShield Security', 'email': 'sales@cybershield.com', 'phone': '+1-555-0104', 'industry': 'Technology'},
            {'name': 'NextGen Software', 'email': 'contact@nextgen.com', 'phone': '+1-555-0105', 'industry': 'Technology'},
            {'name': 'AI Dynamics Corp', 'email': 'info@aidynamics.com', 'phone': '+1-555-0106', 'industry': 'Technology'},
            {'name': 'BlockTech Innovations', 'email': 'hello@blocktech.com', 'phone': '+1-555-0107', 'industry': 'Technology'},
            
            # Healthcare
            {'name': 'MedCare Solutions', 'email': 'contact@medcare.com', 'phone': '+1-555-0201', 'industry': 'Healthcare'},
            {'name': 'HealthTech Partners', 'email': 'info@healthtech.com', 'phone': '+1-555-0202', 'industry': 'Healthcare'},
            {'name': 'Digital Health Systems', 'email': 'sales@digitalhealth.com', 'phone': '+1-555-0203', 'industry': 'Healthcare'},
            {'name': 'BioMed Innovations', 'email': 'contact@biomed.com', 'phone': '+1-555-0204', 'industry': 'Healthcare'},
            {'name': 'TeleMed Solutions', 'email': 'info@telemed.com', 'phone': '+1-555-0205', 'industry': 'Healthcare'},
            
            # Finance
            {'name': 'FinTech Pioneers', 'email': 'contact@fintechpioneers.com', 'phone': '+1-555-0301', 'industry': 'Finance'},
            {'name': 'Investment Analytics', 'email': 'info@investmentanalytics.com', 'phone': '+1-555-0302', 'industry': 'Finance'},
            {'name': 'CryptoTrade Systems', 'email': 'sales@cryptotrade.com', 'phone': '+1-555-0303', 'industry': 'Finance'},
            {'name': 'PaymentGateway Pro', 'email': 'contact@paymentgateway.com', 'phone': '+1-555-0304', 'industry': 'Finance'},
            {'name': 'RiskManagement Plus', 'email': 'info@riskmanagement.com', 'phone': '+1-555-0305', 'industry': 'Finance'},
            
            # Manufacturing
            {'name': 'AutoMate Industries', 'email': 'contact@automate.com', 'phone': '+1-555-0401', 'industry': 'Manufacturing'},
            {'name': 'SmartFactory Solutions', 'email': 'info@smartfactory.com', 'phone': '+1-555-0402', 'industry': 'Manufacturing'},
            {'name': 'Industrial IoT Corp', 'email': 'sales@industrialiot.com', 'phone': '+1-555-0403', 'industry': 'Manufacturing'},
            {'name': 'RoboTech Manufacturing', 'email': 'contact@robotech.com', 'phone': '+1-555-0404', 'industry': 'Manufacturing'},
            {'name': 'Supply Chain Dynamics', 'email': 'info@supplychain.com', 'phone': '+1-555-0405', 'industry': 'Manufacturing'},
            
            # Retail & E-commerce
            {'name': 'E-Commerce Experts', 'email': 'contact@ecommerceexperts.com', 'phone': '+1-555-0501', 'industry': 'Retail'},
            {'name': 'Retail Analytics Pro', 'email': 'info@retailanalytics.com', 'phone': '+1-555-0502', 'industry': 'Retail'},
            {'name': 'Digital Marketplace', 'email': 'sales@digitalmarketplace.com', 'phone': '+1-555-0503', 'industry': 'Retail'},
            {'name': 'Customer Insights Ltd', 'email': 'contact@customerinsights.com', 'phone': '+1-555-0504', 'industry': 'Retail'},
            {'name': 'Omnichannel Solutions', 'email': 'info@omnichannel.com', 'phone': '+1-555-0505', 'industry': 'Retail'},
        ]

        total_clients_created = 0
        for i, salesperson in enumerate(salespeople):
            # Each salesperson gets 20-25 clients
            num_clients = random.randint(20, 25)
            clients_for_sp = random.sample(client_templates, min(num_clients, len(client_templates)))
            
            # Add unique suffix to avoid duplicates
            for j, client_template in enumerate(clients_for_sp):
                unique_email = f"{client_template['email'].split('@')[0]}.{salesperson.username}@{client_template['email'].split('@')[1]}"
                unique_name = f"{client_template['name']} ({client_template['industry']})"
                
                if not Client.objects.filter(email=unique_email, organization=organization).exists():
                    Client.objects.create(
                        client_name=unique_name,
                        email=unique_email,
                        phone_number=client_template['phone'],
                        organization=organization,
                        created_by=salesperson
                    )
                    total_clients_created += 1
            
            self.stdout.write(self.style.SUCCESS(f"📋 {len(clients_for_sp)} clients created for {salesperson.username}"))

        self.stdout.write(self.style.SUCCESS(f"🎯 Total clients created: {total_clients_created}"))

        # 7. Create varied deals for each client (realistic business scenarios)
        self.stdout.write(self.style.HTTP_INFO("--- Creating Realistic Deal Portfolio ---"))
        
        deal_types = [
            {'name': 'Software License', 'value_range': (10000, 50000)},
            {'name': 'Implementation Services', 'value_range': (25000, 100000)},
            {'name': 'Annual Support Contract', 'value_range': (5000, 30000)},
            {'name': 'Custom Development', 'value_range': (50000, 200000)},
            {'name': 'Consulting Services', 'value_range': (15000, 75000)},
            {'name': 'Training & Certification', 'value_range': (3000, 15000)},
            {'name': 'Enterprise Solution', 'value_range': (100000, 500000)},
            {'name': 'Cloud Migration', 'value_range': (30000, 150000)},
            {'name': 'Security Audit', 'value_range': (8000, 40000)},
            {'name': 'Data Analytics Platform', 'value_range': (20000, 80000)},
        ]

        total_deals_created = 0
        for salesperson in salespeople:
            clients = Client.objects.filter(created_by=salesperson)
            
            for client in clients:
                # Each client gets 1-4 deals with varied statuses and timing
                num_deals = random.randint(1, 4)
                
                for _ in range(num_deals):
                    deal_type = random.choice(deal_types)
                    deal_value = Decimal(random.randint(deal_type['value_range'][0], deal_type['value_range'][1]))
                    
                    # Realistic date ranges
                    deal_date = date.today() - timedelta(days=random.randint(0, 180))  # Last 6 months
                    due_date = deal_date + timedelta(days=random.randint(15, 90))  # 15-90 days to close
                    
                    # Realistic status distribution
                    status_weights = [
                        ('pending', 40),  # 40% pending
                        ('won', 35),      # 35% won
                        ('lost', 25)      # 25% lost
                    ]
                    deal_status = random.choices(
                        [status[0] for status in status_weights],
                        weights=[status[1] for status in status_weights]
                    )[0]
                    
                    # Payment status based on deal status
                    if deal_status == 'won':
                        pay_status = random.choices(
                            ['verified', 'partial', 'pending'],
                            weights=[60, 25, 15]  # Most won deals are paid
                        )[0]
                    elif deal_status == 'pending':
                        pay_status = 'pending'
                    else:  # lost
                        pay_status = 'rejected'
                    
                    Deal.objects.create(
                        client_name=client.client_name,
                        deal_value=deal_value,
                        deal_date=deal_date,
                        due_date=due_date,
                        deal_status=deal_status,
                        pay_status=pay_status,
                        created_by=salesperson,
                        organization=organization
                    )
                    total_deals_created += 1
            
            # Calculate and display stats for each salesperson
            sp_deals = Deal.objects.filter(created_by=salesperson)
            won_deals = sp_deals.filter(deal_status='won')
            total_won_value = sum(deal.deal_value for deal in won_deals)
            
            self.stdout.write(self.style.SUCCESS(
                f"💰 {salesperson.username}: {sp_deals.count()} deals, "
                f"{won_deals.count()} won (${total_won_value:,.2f})"
            ))

        self.stdout.write(self.style.SUCCESS(f"🎯 Total deals created: {total_deals_created}"))
        
        # 8. Display final summary
        self.stdout.write(self.style.HTTP_INFO("--- Mock Data Creation Summary ---"))
        self.stdout.write(f"🏢 Organization: {organization.name}")
        self.stdout.write(f"👥 Users: {User.objects.filter(organization=organization).count()}")
        self.stdout.write(f"📋 Clients: {Client.objects.filter(organization=organization).count()}")
        self.stdout.write(f"💼 Deals: {Deal.objects.filter(organization=organization).count()}")
        
        total_deal_value = sum(deal.deal_value for deal in Deal.objects.filter(organization=organization, deal_status='won'))
        self.stdout.write(f"💰 Total Won Value: ${total_deal_value:,.2f}")
        self.stdout.write(self.style.SUCCESS("🎉 Realistic business data created successfully!")) 