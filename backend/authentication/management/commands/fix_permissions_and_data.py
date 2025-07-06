from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from permissions.models import Role
from deals.models import Deal
from clients.models import Client
from authentication.models import User
from datetime import datetime, timedelta
from decimal import Decimal
import random

class Command(BaseCommand):
    help = 'Fix missing permissions for Salesperson role and create recent deals for dashboard'

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("=== Fixing Permissions and Data ==="))
        
        # 1. Fix Salesperson permissions (this is now handled by create_permissions command)
        # self.fix_salesperson_permissions()
        
        # 2. Create recent deals for dashboard (only if needed)
        self.create_recent_deals()
        
        self.stdout.write(self.style.SUCCESS("✅ Data fixes completed successfully!"))

    def create_recent_deals(self):
        self.stdout.write(self.style.HTTP_INFO("--- Creating Recent Deals (if needed) ---"))
        
        # Check if we already have recent deals
        today = datetime.now().date()
        week_ago = today - timedelta(days=7)
        recent_deals_count = Deal.objects.filter(deal_date__gte=week_ago).count()
        
        if recent_deals_count >= 10:
            self.stdout.write(self.style.SUCCESS(f"✅ Already have {recent_deals_count} recent deals, skipping creation"))
            return
        
        # Get users and clients
        users = User.objects.filter(organization__isnull=False, is_active=True)
        clients = Client.objects.all()
        
        if not users.exists() or not clients.exists():
            self.stdout.write(self.style.WARNING("No users or clients found! Skipping deal creation."))
            return
        
        # Create deals for the last 30 days
        deals_created = 0
        
        for i in range(30):  # Last 30 days
            deal_date = today - timedelta(days=i)
            
            # Create 1-3 deals per day
            for _ in range(random.randint(1, 3)):
                user = random.choice(users)
                client = random.choice(clients)
                
                # Skip if this user-client-date combination already exists
                if Deal.objects.filter(
                    created_by=user,
                    client=client,
                    deal_date=deal_date
                ).exists():
                    continue
                
                deal_value = Decimal(random.randint(5000, 50000))
                due_date = deal_date + timedelta(days=random.randint(30, 90))
                
                Deal.objects.create(
                    organization=user.organization,
                    client=client,
                    deal_value=deal_value,
                    deal_date=deal_date,
                    due_date=due_date,
                    payment_status=random.choice(['pending', 'verified', 'partial', 'rejected']),
                    verification_status=random.choice(['pending', 'verified', 'rejected']),
                    client_status=random.choice(['interested', 'not_interested', 'follow_up']),
                    source_type=random.choice(['referral', 'direct', 'marketing', 'social_media']),
                    payment_method=random.choice(['cash', 'bank_transfer', 'cheque', 'online']),
                    deal_remarks=f"Recent deal created for dashboard testing on {deal_date}",
                    created_by=user,
                )
                deals_created += 1
        
        self.stdout.write(self.style.SUCCESS(f"✅ Created {deals_created} recent deals for dashboard")) 