from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from datetime import datetime, timedelta
import random

from clients.models import Client, ClientActivity
from organization.models import Organization
from permissions.models import Role

User = get_user_model()


class Command(BaseCommand):
    help = "Seed the database with sample client data for testing the clients table functionality.\n\n" \
           "• Creates diverse clients with different statuses, satisfaction levels, and realistic data.\n" \
           "• Assigns clients to existing salespersons and organizations.\n" \
           "• Creates client activities for some clients.\n" \
           "The command is idempotent – re-running won't create duplicates."

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=25,
            help='Number of clients to create (default: 25)',
        )

    def handle(self, *args, **options):
        count = options['count']
        self.stdout.write(self.style.NOTICE(f"Seeding {count} client records..."))
        
        with transaction.atomic():
            # Get all organizations
            organizations = list(Organization.objects.all())
            if not organizations:
                self.stdout.write(self.style.ERROR("No organizations found. Please run seed_demo_data first."))
                return

            # Get all salespersons
            salesperson_role = Role.objects.filter(name='Salesperson').first()
            salespersons = list(User.objects.filter(role=salesperson_role)) if salesperson_role else []
            
            # Sample client data
            client_names = [
                "Rajesh Hamal", "Deepika Prasain", "Arjun Karki", "Sita Sharma", "Ram Thapa",
                "Gita Rai", "Krishna Malla", "Sunita Gurung", "Bikash Shrestha", "Anita Lama",
                "Pramod Kharel", "Kamala Bhatta", "Suresh Tamang", "Manju Neupane", "Dipesh Shah",
                "Sabita Pradhan", "Ravi Pandey", "Nirmala Khadka", "Ashok Basnet", "Sarita Koju",
                "Dinesh Adhikari", "Purnima Oli", "Santosh Rana", "Indira Dhakal", "Manoj Regmi",
                "Sheila Gautam", "Narayan Pokhrel", "Kopila Thakuri", "Surendra Joshi", "Rita Bhandari",
                "Umesh Chhetri", "Sushma Acharya", "Deepak Maharjan", "Kavita Kandel", "Rajendra Karmacharya",
                "Bishnu Sapkota", "Geeta Subedi", "Lokendra Rajbhandari", "Sangita Poudel", "Hemant Koirala"
            ]
            
            # Sample companies/organizations for business clients
            business_names = [
                "Tech Solutions Pvt. Ltd.", "Himalayan Traders", "Valley Exports", "Nepal Textiles Co.",
                "Mountain View Hotels", "Kathmandu Consultancy", "Heritage Tours & Travels", 
                "Digital Nepal Services", "Green Energy Solutions", "Everest Construction",
                "Pharma Plus Industries", "Golden Gate Holdings", "Sunrise Education Group",
                "Blue Mountain Logistics", "Crystal Clear Chemicals", "Royal Foods Industries"
            ]
            
            nationalities = [
                "Nepali", "Indian", "Chinese", "Bhutanese", "Tibetan", "American", "British", 
                "Canadian", "Australian", "German", "Japanese", "Korean", "Bangladesh"
            ]
            
            statuses = ['active', 'inactive', 'prospect']
            satisfactions = ['excellent', 'good', 'average', 'poor']
            categories = ['loyal', 'inconsistent', 'occasional']
            
            # Sample remarks
            remarks_templates = [
                "Very responsive and professional client",
                "Needs follow-up for payment terms",
                "Potential for long-term partnership",
                "Requires frequent communication",
                "High-value client with multiple projects",
                "New client, still building relationship",
                "Excellent payment history",
                "Interested in expanding business",
                "Prefers email communication",
                "Regular client with seasonal orders",
                "VIP client - priority handling required",
                "Recently renewed contract",
                "Exploring new service offerings",
                "Reliable partner for 3+ years",
                "Needs technical support assistance"
            ]

            created_count = 0
            
            for i in range(count):
                # Mix of individual and business clients
                is_business = i % 4 == 0  # 25% business clients
                
                if is_business and i < len(business_names):
                    name = business_names[i % len(business_names)]
                    email_base = name.lower().replace(' ', '').replace('&', 'and').replace('.', '').replace(',', '')[:15]
                else:
                    name = client_names[i % len(client_names)]
                    email_base = name.lower().replace(' ', '.')
                
                # Generate unique email
                email = f"{email_base}{i}@{'business' if is_business else 'personal'}.com"
                
                # Check if client already exists
                if Client.objects.filter(email=email).exists():
                    continue
                
                # Random organization
                org = random.choice(organizations)
                
                # Random salesperson from the same organization if available
                org_salespersons = [sp for sp in salespersons if sp.organization == org]
                salesperson = random.choice(org_salespersons) if org_salespersons else random.choice(salespersons) if salespersons else None
                
                # Random data
                status = random.choice(statuses)
                satisfaction = random.choice(satisfactions)
                category = random.choice(categories)
                nationality = random.choice(nationalities)
                
                # Generate phone number
                phone = f"+977-{random.randint(980, 986)}{random.randint(1000000, 9999999)}"
                
                # Generate value based on client type and status
                if status == 'active':
                    value = random.uniform(50000, 500000)
                elif status == 'prospect':
                    value = random.uniform(10000, 100000)
                else:  # inactive
                    value = random.uniform(5000, 50000)
                
                # Generate dates
                last_contact = None
                expected_close = None
                
                if status == 'active':
                    last_contact = timezone.now() - timedelta(days=random.randint(1, 30))
                    expected_close = timezone.now().date() + timedelta(days=random.randint(30, 180))
                elif status == 'prospect':
                    last_contact = timezone.now() - timedelta(days=random.randint(7, 60))
                    expected_close = timezone.now().date() + timedelta(days=random.randint(60, 365))
                
                # Contact details
                primary_contact = name.split()[0] if not is_business else f"{random.choice(['Mr.', 'Ms.'])} {random.choice(['Manager', 'Director', 'Executive'])}"
                
                # Create client
                client = Client.objects.create(
                    client_name=name,
                    email=email,
                    phone_number=phone,
                    category=category,
                    salesperson=salesperson,
                    last_contact=last_contact,
                    expected_close=expected_close,
                    value=value,
                    status=status,
                    satisfaction=satisfaction,
                    primary_contact_name=primary_contact,
                    primary_contact_phone=phone,
                    nationality=nationality,
                    remarks=random.choice(remarks_templates),
                    organization=org,
                    created_by=salesperson or User.objects.filter(organization=org).first()
                )
                
                # Create some activities for active clients
                if status == 'active' and random.random() < 0.7:  # 70% chance
                    activity_types = ['meeting', 'call', 'email', 'note']
                    activity_descriptions = [
                        "Initial consultation meeting completed",
                        "Follow-up call regarding project requirements",
                        "Sent proposal document via email",
                        "Client showed interest in additional services",
                        "Discussed project timeline and deliverables",
                        "Payment terms negotiated and agreed",
                        "Project kick-off meeting scheduled",
                        "Regular check-in call completed",
                        "Contract renewal discussion",
                        "Technical requirements gathering session"
                    ]
                    
                    # Create 1-3 activities per active client
                    num_activities = random.randint(1, 3)
                    for j in range(num_activities):
                        ClientActivity.objects.create(
                            client=client,
                            type=random.choice(activity_types),
                            description=random.choice(activity_descriptions),
                            created_by=client.created_by,
                            timestamp=timezone.now() - timedelta(days=random.randint(1, 30))
                        )
                
                created_count += 1
                
                if created_count % 10 == 0:
                    self.stdout.write(f"Created {created_count} clients...")
            
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully created {created_count} clients with activities.\n"
                    f"Status distribution: Active, Inactive, Prospect\n"
                    f"Satisfaction levels: Excellent, Good, Average, Poor\n"
                    f"Categories: Loyal, Inconsistent, Occasional"
                )
            ) 