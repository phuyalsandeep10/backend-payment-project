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
    help = "Initializes the application with a superuser and mock data. This command creates TechCorp organization and sample data."

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting application initialization..."))

        try:
            # Always run setup - don't check for existing superusers
            self.setup_superadmin()
            self.create_default_roles()
            self.create_mock_data()
            self.stdout.write(self.style.SUCCESS("Application initialization completed successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"An error occurred during initialization: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))

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

    def create_default_roles(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Default Role Templates ---"))
        
        # Import and run the default roles creation
        from django.core.management import call_command
        try:
            call_command('create_default_roles')
            self.stdout.write(self.style.SUCCESS("✅ Default roles and permissions created via create_default_roles command"))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"⚠️ Could not run create_default_roles command: {e}"))
            # Continue with basic role creation
            self.create_basic_roles()

    def create_basic_roles(self):
        """Fallback method to create basic roles if the command fails"""
        self.stdout.write(self.style.HTTP_INFO("Creating basic roles as fallback..."))
        
        basic_roles = [
            'Organization Admin',
            'Sales Manager', 
            'Team Head',
            'Senior Salesperson',
            'Salesperson',
            'Verifier',
            'Team Member'
        ]
        
        for role_name in basic_roles:
            role, created = Role.objects.get_or_create(name=role_name, organization=None)
            if created:
                self.stdout.write(self.style.SUCCESS(f"✅ Created basic role: {role_name}"))

    def create_mock_data(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Realistic Mock Data Following Business Flow ---"))

        # 1. Create TechCorp Solutions Organization
        org_name = "TechCorp Solutions"
        organization, created = Organization.objects.get_or_create(
            name=org_name,
            defaults={'sales_goal': Decimal("1500000.00")}  # 1.5M annual sales goal
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f"📊 Organization '{org_name}' created."))
        else:
            self.stdout.write(self.style.WARNING(f"Organization '{org_name}' already exists. Using existing."))

        # 2. Create organization-specific roles based on templates
        org_roles = {}
        role_names = ["Organization Admin", "Sales Manager", "Team Head", "Senior Salesperson", 
                     "Salesperson", "Verifier", "Team Member"]
        
        for role_name in role_names:
            # Try to get template role, create basic one if not found
            try:
                template_role = Role.objects.get(name=role_name, organization=None)
            except Role.DoesNotExist:
                template_role = Role.objects.create(name=role_name, organization=None)
                
            org_role, created = Role.objects.get_or_create(
                name=role_name, 
                organization=organization
            )
            if created and hasattr(template_role, 'permissions'):
                # Copy permissions from template if they exist
                org_role.permissions.set(template_role.permissions.all())
            org_roles[role_name] = org_role

        self.stdout.write(self.style.SUCCESS(f"🎭 Organization-specific roles created for {organization.name}"))

        # 3. Create Organization Admin
        org_admin_email = "admin@techcorp.com"
        org_admin_password = "admin123"
        if not User.objects.filter(email=org_admin_email).exists():
            org_admin = User.objects.create_user(
                username='orgadmin',
                email=org_admin_email,
                password=org_admin_password,
                role=org_roles["Organization Admin"],
                organization=organization,
                is_staff=True
            )
            org_admin.set_password(org_admin_password)
            org_admin.is_active = True
            org_admin.save()
            self.stdout.write(self.style.SUCCESS(f"👑 Organization Admin '{org_admin_email}' created."))
            self.stdout.write(self.style.SUCCESS(f"✅ Login: {org_admin_email} / {org_admin_password}"))
        else:
            org_admin = User.objects.get(email=org_admin_email)
            self.stdout.write(self.style.WARNING(f"Org Admin '{org_admin_email}' already exists."))

        # 4. Create Sales Manager
        sales_manager_email = "manager@techcorp.com"
        sales_manager_password = "manager123"
        if not User.objects.filter(email=sales_manager_email).exists():
            sales_manager = User.objects.create_user(
                username='salesmanager',
                email=sales_manager_email,
                password=sales_manager_password,
                role=org_roles["Sales Manager"],
                organization=organization,
                sales_target=Decimal("500000.00")
            )
            sales_manager.set_password(sales_manager_password)
            sales_manager.is_active = True
            sales_manager.save()
            self.stdout.write(self.style.SUCCESS(f"🎯 Sales Manager '{sales_manager_email}' created."))
            self.stdout.write(self.style.SUCCESS(f"✅ Login: {sales_manager_email} / {sales_manager_password}"))
        else:
            sales_manager = User.objects.get(email=sales_manager_email)

        # 5. Create Salespeople
        salesperson_data = [
            {
                'username': 'john.smith',
                'email': 'john.smith@techcorp.com',
                'password': 'john123',
                'role': org_roles["Senior Salesperson"],
                'target': Decimal("300000.00"),
                'name': 'John Smith'
            },
            {
                'username': 'sarah.johnson',
                'email': 'sarah.johnson@techcorp.com',
                'password': 'sarah123',
                'role': org_roles["Salesperson"],
                'target': Decimal("200000.00"),
                'name': 'Sarah Johnson'
            },
            {
                'username': 'mike.davis',
                'email': 'mike.davis@techcorp.com',
                'password': 'mike123',
                'role': org_roles["Salesperson"],
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
                self.stdout.write(self.style.SUCCESS(f"👤 {sp_data['name']} ({sp_data['role'].name}) created."))
                self.stdout.write(self.style.SUCCESS(f"✅ Login: {sp_data['email']} / {sp_data['password']}"))
            else:
                salespeople.append(User.objects.get(email=sp_data['email']))

        # 6. Create realistic clients for each salesperson
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

        # 7. Create varied deals for each client
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
        
        # Display login credentials for easy access
        self.stdout.write(self.style.HTTP_INFO("--- Login Credentials ---"))
        self.stdout.write(f"🔐 Super Admin: admin@example.com / defaultpass")
        self.stdout.write(f"🔐 Org Admin: admin@techcorp.com / admin123")
        self.stdout.write(f"🔐 Sales Manager: manager@techcorp.com / manager123")
        self.stdout.write(f"🔐 John Smith (Senior): john.smith@techcorp.com / john123")
        self.stdout.write(f"🔐 Sarah Johnson: sarah.johnson@techcorp.com / sarah123")
        self.stdout.write(f"🔐 Mike Davis: mike.davis@techcorp.com / mike123")
        
        self.stdout.write(self.style.SUCCESS("🎉 Realistic business data created successfully!"))
        self.stdout.write(self.style.HTTP_INFO("💡 Use the /auth/login/direct/ endpoint to login without OTP verification")) 