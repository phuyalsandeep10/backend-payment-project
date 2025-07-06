import os
import random
from datetime import date, timedelta
from decimal import Decimal

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone

from authentication.models import User
from clients.models import Client
from commission.models import Commission
from deals.models import Deal, Payment
from notifications.models import NotificationSettings, NotificationTemplate
from organization.models import Organization
from permissions.models import Role
from project.models import Project
from team.models import Team


class Command(BaseCommand):
    help = "Initializes the application with a superuser and mock data. This command creates TechCorp organization and sample data."

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting application initialization..."))

        try:
            # Clear existing mock data to ensure a clean slate
            self.clear_mock_data()

            # Always run setup - don't check for existing superusers
            self.setup_superadmin()
            self.create_default_roles()
            self.create_mock_data()
            self.stdout.write(self.style.SUCCESS("Application initialization completed successfully!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"An error occurred during initialization: {e}"))
            import traceback
            self.stdout.write(self.style.ERROR(f"Traceback: {traceback.format_exc()}"))

    def clear_mock_data(self):
        self.stdout.write(self.style.WARNING("--- Clearing existing mock data ---"))
        try:
            # We only want to delete the mock organization, not all organizations
            org_to_delete = Organization.objects.filter(name="TechCorp Solutions")
            if org_to_delete.exists():
                # This will cascade and delete users, clients, deals, etc.
                org_to_delete.delete()
                self.stdout.write(self.style.SUCCESS("✅ Cleared mock data for 'TechCorp Solutions'."))
            else:
                self.stdout.write(self.style.HTTP_INFO("No existing 'TechCorp Solutions' mock data to clear."))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error clearing mock data: {e}"))


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
                first_name="Super",
                last_name="Admin",
                contact_number="+10000000000",
                role=super_admin_role
            )
            
            # Ensure the password is set correctly and user is active
            superuser.set_password(admin_password)
            superuser.is_active = True
            superuser.is_staff = True
            superuser.is_superuser = True
            superuser.save()
            
            # Create notification settings for superuser
            NotificationSettings.objects.get_or_create(user=superuser)

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
                first_name="Org",
                last_name="Admin",
                contact_number="+11111111111",
                role=org_roles["Organization Admin"],
                organization=organization,
                is_staff=True
            )
            org_admin.set_password(org_admin_password)
            org_admin.is_active = True
            org_admin.save()
            NotificationSettings.objects.get_or_create(user=org_admin)
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
                first_name="Sales",
                last_name="Manager",
                contact_number="+12222222222",
                role=org_roles["Sales Manager"],
                organization=organization,
                sales_target=Decimal("500000.00")
            )
            sales_manager.set_password(sales_manager_password)
            sales_manager.is_active = True
            sales_manager.save()
            NotificationSettings.objects.get_or_create(user=sales_manager)
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
                'first_name': 'John',
                'last_name': 'Smith',
                'contact_number': '+13333333333',
            },
            {
                'username': 'sarah.johnson',
                'email': 'sarah.johnson@techcorp.com',
                'password': 'sarah123',
                'role': org_roles["Salesperson"],
                'target': Decimal("200000.00"),
                'first_name': 'Sarah',
                'last_name': 'Johnson',
                'contact_number': '+14444444444',
            },
            {
                'username': 'mike.davis',
                'email': 'mike.davis@techcorp.com',
                'password': 'mike123',
                'role': org_roles["Salesperson"],
                'target': Decimal("250000.00"),
                'first_name': 'Mike',
                'last_name': 'Davis',
                'contact_number': '+15555555555',
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
                    sales_target=sp_data['target'],
                    first_name=sp_data['first_name'],
                    last_name=sp_data['last_name'],
                    contact_number=sp_data['contact_number']
                )
                salesperson.set_password(sp_data['password'])
                salesperson.is_active = True
                salesperson.save()
                NotificationSettings.objects.get_or_create(user=salesperson)
                salespeople.append(salesperson)
                self.stdout.write(self.style.SUCCESS(f"👤 {sp_data['first_name']} {sp_data['last_name']} ({sp_data['role'].name}) created."))
                self.stdout.write(self.style.SUCCESS(f"✅ Login: {sp_data['email']} / {sp_data['password']}"))
            else:
                salespeople.append(User.objects.get(email=sp_data['email']))

        # 6. Create Projects and Teams
        self.stdout.write(self.style.HTTP_INFO("--- Creating Projects and Teams ---"))
        project_names = ["Project Alpha", "Project Beta", "Project Gamma"]
        projects = []
        for name in project_names:
            project, _ = Project.objects.get_or_create(name=name)
            projects.append(project)
        self.stdout.write(self.style.SUCCESS(f"🛠️  Created {len(projects)} projects."))

        sales_team, _ = Team.objects.get_or_create(
            name="Sales Team Alpha",
            organization=organization,
            defaults={
                'team_lead': sales_manager,
                'contact_number': '+19999999999'
            }
        )
        sales_team.members.set(salespeople)
        sales_team.projects.set(projects)
        self.stdout.write(self.style.SUCCESS(f"🤝 Created Sales Team '{sales_team.name}' with {sales_team.members.count()} members and {sales_team.projects.count()} projects."))


        # 7. Create realistic clients for each salesperson
        self.stdout.write(self.style.HTTP_INFO("--- Creating Diverse Client Portfolio ---"))
        
        # Client templates with varied industries and sizes
        client_templates = [
            # Tech Sector
            {'name': 'InnovateTech Solutions', 'email': 'contact@innovatetech.com', 'phone': '+1-555-0101', 'industry': 'Technology', 'nationality': 'USA', 'status': 'active'},
            {'name': 'CloudFirst Systems', 'email': 'info@cloudfirst.com', 'phone': '+1-555-0102', 'industry': 'Technology', 'nationality': 'Canada', 'status': 'active'},
            {'name': 'DataStream Analytics', 'email': 'hello@datastream.com', 'phone': '+1-555-0103', 'industry': 'Technology', 'nationality': 'UK', 'status': 'prospect'},
            {'name': 'CyberShield Security', 'email': 'sales@cybershield.com', 'phone': '+1-555-0104', 'industry': 'Technology', 'nationality': 'Germany', 'status': 'active'},
            {'name': 'NextGen Software', 'email': 'contact@nextgen.com', 'phone': '+1-555-0105', 'industry': 'Technology', 'nationality': 'USA', 'status': 'inactive'},
            {'name': 'AI Dynamics Corp', 'email': 'info@aidynamics.com', 'phone': '+1-555-0106', 'industry': 'Technology', 'nationality': 'France', 'status': 'prospect'},
            {'name': 'BlockTech Innovations', 'email': 'hello@blocktech.com', 'phone': '+1-555-0107', 'industry': 'Technology', 'nationality': 'Japan', 'status': 'active'},
            
            # Healthcare
            {'name': 'MedCare Solutions', 'email': 'contact@medcare.com', 'phone': '+1-555-0201', 'industry': 'Healthcare', 'nationality': 'USA', 'status': 'active'},
            {'name': 'HealthTech Partners', 'email': 'info@healthtech.com', 'phone': '+1-555-0202', 'industry': 'Healthcare', 'nationality': 'Australia', 'status': 'prospect'},
            {'name': 'Digital Health Systems', 'email': 'sales@digitalhealth.com', 'phone': '+1-555-0203', 'industry': 'Healthcare', 'nationality': 'USA', 'status': 'active'},
            {'name': 'BioMed Innovations', 'email': 'contact@biomed.com', 'phone': '+1-555-0204', 'industry': 'Healthcare', 'nationality': 'Switzerland', 'status': 'inactive'},
            {'name': 'TeleMed Solutions', 'email': 'info@telemed.com', 'phone': '+1-555-0205', 'industry': 'Healthcare', 'nationality': 'India', 'status': 'prospect'},
            
            # Finance
            {'name': 'FinTech Pioneers', 'email': 'contact@fintechpioneers.com', 'phone': '+1-555-0301', 'industry': 'Finance', 'nationality': 'UK', 'status': 'active'},
            {'name': 'Investment Analytics', 'email': 'info@investmentanalytics.com', 'phone': '+1-555-0302', 'industry': 'Finance', 'nationality': 'USA', 'status': 'active'},
            {'name': 'CryptoTrade Systems', 'email': 'sales@cryptotrade.com', 'phone': '+1-555-0303', 'industry': 'Finance', 'nationality': 'Singapore', 'status': 'prospect'},
            {'name': 'PaymentGateway Pro', 'email': 'contact@paymentgateway.com', 'phone': '+1-555-0304', 'industry': 'Finance', 'nationality': 'USA', 'status': 'active'},
            {'name': 'RiskManagement Plus', 'email': 'info@riskmanagement.com', 'phone': '+1-555-0305', 'industry': 'Finance', 'nationality': 'Germany', 'status': 'inactive'},
            
            # Manufacturing
            {'name': 'AutoMate Industries', 'email': 'contact@automate.com', 'phone': '+1-555-0401', 'industry': 'Manufacturing', 'nationality': 'Japan', 'status': 'active'},
            {'name': 'SmartFactory Solutions', 'email': 'info@smartfactory.com', 'phone': '+1-555-0402', 'industry': 'Manufacturing', 'nationality': 'China', 'status': 'prospect'},
            {'name': 'Industrial IoT Corp', 'email': 'sales@industrialiot.com', 'phone': '+1-555-0403', 'industry': 'Manufacturing', 'nationality': 'USA', 'status': 'active'},
            {'name': 'RoboTech Manufacturing', 'email': 'contact@robotech.com', 'phone': '+1-555-0404', 'industry': 'Manufacturing', 'nationality': 'South Korea', 'status': 'inactive'},
            {'name': 'Supply Chain Dynamics', 'email': 'info@supplychain.com', 'phone': '+1-555-0405', 'industry': 'Manufacturing', 'nationality': 'USA', 'status': 'prospect'},
            
            # Retail & E-commerce
            {'name': 'E-Commerce Experts', 'email': 'contact@ecommerceexperts.com', 'phone': '+1-555-0501', 'industry': 'Retail', 'nationality': 'USA', 'status': 'active'},
            {'name': 'Retail Analytics Pro', 'email': 'info@retailanalytics.com', 'phone': '+1-555-0502', 'industry': 'Retail', 'nationality': 'UK', 'status': 'prospect'},
            {'name': 'Digital Marketplace', 'email': 'sales@digitalmarketplace.com', 'phone': '+1-555-0503', 'industry': 'Retail', 'nationality': 'Canada', 'status': 'active'},
            {'name': 'Customer Insights Ltd', 'email': 'contact@customerinsights.com', 'phone': '+1-555-0504', 'industry': 'Retail', 'nationality': 'USA', 'status': 'inactive'},
            {'name': 'Omnichannel Solutions', 'email': 'info@omnichannel.com', 'phone': '+1-555-0505', 'industry': 'Retail', 'nationality': 'Australia', 'status': 'prospect'},
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
                        created_by=salesperson,
                        nationality=client_template['nationality'],
                        status=client_template['status'],
                        satisfaction=random.choice([c[0] for c in Client.SATISFACTION_CHOICES if c[0] is not None] or ['good']),
                        remarks="Initial contact made. Prospect for a new deal." if client_template['status'] == 'prospect' else "Existing client."
                    )
                    total_clients_created += 1
            
            self.stdout.write(self.style.SUCCESS(f"📋 {len(clients_for_sp)} clients created for {salesperson.username}"))

        self.stdout.write(self.style.SUCCESS(f"🎯 Total clients created: {total_clients_created}"))

        # 8. Create varied deals for each client
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
                        ('verified', 35),      # 35% won -> verified
                        ('rejected', 25)      # 25% lost -> rejected
                    ]
                    deal_status = random.choices(
                        [status[0] for status in status_weights],
                        weights=[status[1] for status in status_weights]
                    )[0]
                    
                    # Payment status based on deal status
                    if deal_status == 'verified':
                        pay_status = random.choices(
                            ['full_payment', 'partial_payment', 'initial payment'],
                            weights=[60, 25, 15]  # Most won deals are paid
                        )[0]
                    elif deal_status == 'pending':
                        pay_status = 'initial payment'
                    else:  # rejected
                        pay_status = 'initial payment' # or some other default
                    
                    Deal.objects.create(
                        client_name=client.client_name,
                        deal_value=deal_value,
                        deal_date=deal_date,
                        due_date=due_date,
                        deal_status=deal_status,
                        pay_status=pay_status,
                        created_by=salesperson,
                        organization=organization,
                        source_type=random.choice([s[0] for s in Deal.SOURCE_TYPES]),
                        payment_method=random.choice([p[0] for p in Deal.PAYMENT_METHOD_CHOICES]),
                        deal_remarks=f"Deal for {deal_type['name']}."
                    )
                    total_deals_created += 1
            
            # Calculate and display stats for each salesperson
            sp_deals = Deal.objects.filter(created_by=salesperson)
            won_deals = sp_deals.filter(deal_status='verified')
            total_won_value = sum(deal.deal_value for deal in won_deals)
            
            self.stdout.write(self.style.SUCCESS(
                f"💰 {salesperson.username}: {sp_deals.count()} deals, "
                f"{won_deals.count()} won (${total_won_value:,.2f})"
            ))

        self.stdout.write(self.style.SUCCESS(f"🎯 Total deals created: {total_deals_created}"))
        
        # 9. Create Payments for Deals
        self.stdout.write(self.style.HTTP_INFO("--- Creating Payment Records ---"))
        deals_to_pay = Deal.objects.filter(pay_status__in=['partial_payment', 'full_payment'])
        payments_created = 0
        for deal in deals_to_pay:
            if deal.pay_status == 'full_payment':
                amount = deal.deal_value
            else: # partial_payment
                amount = deal.deal_value * Decimal(random.uniform(0.2, 0.8))
            
            Payment.objects.create(
                deal=deal,
                payment_date=deal.deal_date + timedelta(days=random.randint(1, 10)),
                received_amount=amount.quantize(Decimal('0.01')),
                payment_type=deal.pay_status,
                payment_remarks=f"Payment for deal {deal.deal_id}",
                cheque_number = f"CHEQUE-{random.randint(1000,9999)}" if deal.payment_method == 'cheque' else ""
            )
            payments_created += 1
        self.stdout.write(self.style.SUCCESS(f"🧾 Created {payments_created} payment records."))

        # 10. Create Commissions
        self.stdout.write(self.style.HTTP_INFO("--- Creating Commission Records ---"))
        commissions_created = 0
        for salesperson in salespeople:
            # For simplicity, creating one commission record per salesperson for last quarter
            today = date.today()
            start_of_quarter = date(today.year, 3 * ((today.month - 1) // 3) + 1, 1)
            end_of_quarter = start_of_quarter + timedelta(days=90) # approx

            sales_in_period = Deal.objects.filter(
                created_by=salesperson,
                deal_status='verified',
                deal_date__range=(start_of_quarter, end_of_quarter)
            ).aggregate(total=Sum('deal_value'))['total'] or Decimal('0')

            if sales_in_period > 0:
                Commission.objects.create(
                    user=salesperson,
                    organization=organization,
                    total_sales=sales_in_period,
                    start_date=start_of_quarter,
                    end_date=end_of_quarter,
                    commission_percentage=Decimal('5.00') # example percentage
                )
                commissions_created += 1
        self.stdout.write(self.style.SUCCESS(f"💵 Created {commissions_created} commission records."))

        # 11. Create Notification Templates
        self.stdout.write(self.style.HTTP_INFO("--- Creating Notification Templates ---"))
        templates = [
            {
                'notification_type': 'deal_status_changed',
                'title_template': 'Deal Status Updated: {{deal.client_name}}',
                'message_template': 'The status of deal {{deal.deal_id}} for client {{deal.client_name}} has been updated to {{deal.deal_status}}.',
            },
            {
                'notification_type': 'payment_received',
                'title_template': 'Payment Received for {{deal.client_name}}',
                'message_template': 'A payment of ${{payment.received_amount}} has been received for deal {{deal.deal_id}}.',
            }
        ]
        templates_created = 0
        for t in templates:
            _, created = NotificationTemplate.objects.get_or_create(
                notification_type=t['notification_type'],
                defaults=t
            )
            if created:
                templates_created += 1
        self.stdout.write(self.style.SUCCESS(f"✉️ Created {templates_created} notification templates."))

        # 12. Display final summary
        self.stdout.write(self.style.HTTP_INFO("--- Mock Data Creation Summary ---"))
        self.stdout.write(f"🏢 Organization: {organization.name}")
        self.stdout.write(f"👥 Users: {User.objects.filter(organization=organization).count()}")
        self.stdout.write(f"📋 Clients: {Client.objects.filter(organization=organization).count()}")
        self.stdout.write(f"💼 Deals: {Deal.objects.filter(organization=organization).count()}")
        
        total_deal_value = sum(deal.deal_value for deal in Deal.objects.filter(organization=organization, deal_status='verified'))
        self.stdout.write(f"💰 Total Won Value: ${total_deal_value:,.2f}")
        
        # Display login credentials for easy access
        self.stdout.write(self.style.HTTP_INFO("--- Login Credentials ---"))
        self.stdout.write(f"🔐 Super Admin: admin@example.com / defaultpass")
        self.stdout.write(f"🔐 Org Admin: admin@techcorp.com / admin123")
        self.stdout.write(f"🔐 Sales Manager: manager@techcorp.com / manager123")
        self.stdout.write(f"🔐 John Smith (Senior): john.smith@techcorp.com / john123")
        self.stdout.write(f"🔐 Sarah Johnson: sarah.johnson@techcorp.com / sarah123")
        self.stdout.write(f"🔐 Mike Davis: mike.davis@techcorp.com / mike123")
        
        # Specifically adjust sales for Sarah Johnson after all other data is created
        self.stdout.write(self.style.HTTP_INFO("--- Adjusting Sales for Sarah Johnson ---"))
        try:
            sarah = User.objects.get(email='sarah.johnson@techcorp.com')
            
            # Delete any deals that might have been created for her by the general logic
            Deal.objects.filter(created_by=sarah).delete()

            # Create two specific deals that sum to $40,000
            client1, _ = Client.objects.get_or_create(
                client_name="Fixed Deal Client A", 
                organization=organization, 
                created_by=sarah,
                defaults={
                    'email': 'contact@fixeddeal-a.com',
                    'phone_number': '+1-555-1111',
                    'nationality': 'USA',
                    'status': 'active',
                }
            )
            deal1 = Deal.objects.create(
                created_by=sarah, organization=organization, client_name=client1.client_name,
                deal_value=Decimal('25000.00'), deal_date=timezone.now().date(),
                due_date=timezone.now().date() + timedelta(days=30),
                pay_status='full_payment', deal_status='verified',
                source_type='referral', payment_method='bank'
            )
            Payment.objects.create(deal=deal1, payment_date=timezone.now().date(), received_amount=deal1.deal_value, payment_type='full_payment', cheque_number='BANK-001')
            
            client2, _ = Client.objects.get_or_create(
                client_name="Fixed Deal Client B", 
                organization=organization, 
                created_by=sarah,
                defaults={
                    'email': 'contact@fixeddeal-b.com',
                    'phone_number': '+1-555-2222',
                    'nationality': 'Canada',
                    'status': 'active',
                }
            )
            deal2 = Deal.objects.create(
                created_by=sarah, organization=organization, client_name=client2.client_name,
                deal_value=Decimal('15000.00'), deal_date=timezone.now().date(),
                due_date=timezone.now().date() + timedelta(days=30),
                pay_status='full_payment', deal_status='verified',
                source_type='linkedin', payment_method='wallet'
            )
            Payment.objects.create(deal=deal2, payment_date=timezone.now().date(), received_amount=deal2.deal_value, payment_type='full_payment', cheque_number='WALLET-002')

            total_sales = Deal.objects.filter(created_by=sarah, deal_status='verified').aggregate(total=Sum('deal_value'))['total'] or Decimal('0')
            self.stdout.write(self.style.SUCCESS(f"✅ Adjusted deals for Sarah Johnson. New total sales: ${total_sales:,.2f}"))

        except User.DoesNotExist:
            self.stdout.write(self.style.WARNING("User 'sarah.johnson@techcorp.com' not found."))

        self.stdout.write(self.style.SUCCESS("🎉 Realistic business data created successfully!"))
        self.stdout.write(self.style.HTTP_INFO("💡 Use the /auth/login/direct/ endpoint to login without OTP verification")) 