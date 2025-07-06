from django.core.management.base import BaseCommand
from django.db import transaction
from authentication.models import User
from clients.models import Client
from deals.models import Deal, Payment, ActivityLog
from project.models import Project
from commission.models import Commission
from notifications.models import Notification, NotificationTemplate
from datetime import datetime, timedelta
from decimal import Decimal
import random
from faker import Faker

fake = Faker()

class Command(BaseCommand):
    help = 'Generates a rich and varied dataset for all API endpoints for thorough testing.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            help='Username to focus data generation on. Creates a rich dataset for this specific user.',
            default=None
        )

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("--- Generating Rich & Varied Mock Data for All Endpoints ---"))
        
        target_username = options['username']
        target_user = None
        users = []

        if target_username:
            # If a username is provided, focus on that user
            target_user = User.objects.filter(username=target_username).first()
            if not target_user:
                self.stdout.write(self.style.ERROR(f"User '{target_username}' not found. Cannot generate targeted data."))
                return
            self.stdout.write(self.style.SUCCESS(f"🎯 Focusing data generation on user: {target_username}"))
            users = [target_user]
        else:
            # If no username is provided, check for a "first run" for the default salesperson
            salesperson_user = User.objects.filter(username='salesperson').first()
            if salesperson_user:
                has_data = Deal.objects.filter(
                    created_by=salesperson_user,
                    deal_remarks__icontains="Rich testing deal"
                ).exists()

                if not has_data:
                    self.stdout.write(self.style.SUCCESS("🚀 First run detected for 'salesperson'. Generating a rich, targeted dataset for this user automatically."))
                    target_user = salesperson_user
                    users = [target_user]

            # If it's not a targeted run or a first run for salesperson, generate for all users
            if not users:
                self.stdout.write(self.style.WARNING("Standard run: Generating general data for all users. Use --username to target a specific user."))
                manager = User.objects.filter(username='salesmanager').first()
                if manager:
                    users = list(User.objects.filter(organization=manager.organization))

        if not users:
            self.stdout.write(self.style.ERROR("No users found to generate data for. Please run 'initialize_app' first."))
            return

        clients = list(Client.objects.all())
        if len(clients) < 5:
            self.stdout.write(self.style.ERROR("Not enough clients found. Please run 'initialize_app' first."))
            return
            
        # Clean up old test data to prevent bloat
        self.cleanup_old_data(target_user)

        # Ensure all necessary notification templates exist before creating data
        self.setup_notification_templates()

        # Create varied data
        all_deals = []
        all_deals.extend(self.create_deals_for_period(users, clients, 'daily'))
        all_deals.extend(self.create_deals_for_period(users, clients, 'weekly'))
        all_deals.extend(self.create_deals_for_period(users, clients, 'monthly'))
        all_deals.extend(self.create_deals_for_period(users, clients, 'yearly'))

        # Create related data for the deals
        self.create_related_data(all_deals, users)

        self.stdout.write(self.style.SUCCESS("✅ Rich mock data generated successfully for all endpoints!"))

    def setup_notification_templates(self):
        self.stdout.write(self.style.HTTP_INFO("  - Setting up notification templates..."))
        templates_to_create = [
            {
                'notification_type': 'deal_verified', 
                'title_template': 'Deal Verified: {{deal.id}}',
                'message_template': 'Your deal for {{deal.client.name}} has been verified.'
            },
            {
                'notification_type': 'project_created', 
                'title_template': 'Project Created: {{project.name}}',
                'message_template': 'A new project has been created: {{project.name}}.'
            },
            {
                'notification_type': 'commission_created', 
                'title_template': 'New Commission Record',
                'message_template': 'A new commission record has been created for your sales of {{commission.total_sales}}.'
            }
        ]
        
        for t_data in templates_to_create:
            NotificationTemplate.objects.get_or_create(
                notification_type=t_data['notification_type'],
                defaults=t_data
            )
        self.stdout.write(self.style.SUCCESS("  - Notification templates are set up."))

    def cleanup_old_data(self, target_user=None):
        self.stdout.write(self.style.HTTP_INFO("  - Cleaning up old generated test data..."))
        remark_filter = "Rich testing deal"
        
        deals_to_delete = Deal.objects.filter(deal_remarks__icontains=remark_filter)
        projects_to_delete = Project.objects.filter(description__icontains=remark_filter)
        notifications_to_delete = Notification.objects.filter(message__icontains=remark_filter)
        commissions_to_delete = Commission.objects.all()

        if target_user:
            deals_to_delete = deals_to_delete.filter(created_by=target_user)
            projects_to_delete = projects_to_delete.filter(created_by=target_user)
            notifications_to_delete = notifications_to_delete.filter(recipient=target_user)
            commissions_to_delete = commissions_to_delete.filter(user=target_user)


        # Deleting payments and activity logs via CASCADE from deals
        deleted_deals, _ = deals_to_delete.delete()
        deleted_projects, _ = projects_to_delete.delete()
        deleted_commissions, _ = commissions_to_delete.delete()
        deleted_notifications, _ = notifications_to_delete.delete()
        
        self.stdout.write(self.style.SUCCESS(f"  - Deleted {deleted_deals} deals, {deleted_projects} projects, {deleted_commissions} commissions, {deleted_notifications} notifications for the targeted scope."))

    def create_deals_for_period(self, users, clients, period):
        self.stdout.write(f"  - Creating data for period: {period}")
        today = datetime.now().date()
        deals_created = []
        is_targeted_run = len(users) == 1
        target_user = users[0] if is_targeted_run else None

        # Define number of deals to create
        if period == 'daily':
            count = 20 if is_targeted_run else random.randint(3, 5)
            for _ in range(count):
                deals_created.append(self.create_single_deal(target_user or random.choice(users), clients, today))
        
        elif period == 'weekly':
            count_per_day = 5 if is_targeted_run else random.randint(2, 4)
            for i in range(7):
                date = today - timedelta(days=i)
                for _ in range(count_per_day):
                    deals_created.append(self.create_single_deal(target_user or random.choice(users), clients, date))

        elif period == 'monthly':
            count_per_day = 3 if is_targeted_run else random.randint(1, 3)
            for i in range(0, 30, 2):
                date = today - timedelta(days=i)
                for _ in range(count_per_day):
                    deals_created.append(self.create_single_deal(target_user or random.choice(users), clients, date))
        
        elif period == 'yearly':
            count_per_month = 2 if is_targeted_run else random.randint(5, 10)
            for i in range(12):
                month_date = today - timedelta(days=i * 30)
                date = month_date.replace(day=random.randint(1, 28))
                for _ in range(count_per_month):
                    deals_created.append(self.create_single_deal(target_user or random.choice(users), clients, date))
        
        self.stdout.write(self.style.SUCCESS(f"    - Created {len(deals_created)} deals for {period} view."))
        return deals_created

    def create_single_deal(self, user, clients, deal_date):
        client = random.choice(clients)
        deal_value = Decimal(random.randint(1000, 75000))
        
        deal = Deal.objects.create(
            organization=user.organization,
            client=client,
            deal_value=deal_value,
            deal_date=deal_date,
            due_date=deal_date + timedelta(days=random.randint(30, 90)),
            payment_status=random.choice([choice[0] for choice in Deal.PAYMENT_STATUS_CHOICES]),
            verification_status=random.choice([choice[0] for choice in Deal.DEAL_STATUS]),
            client_status=random.choice([choice[0] for choice in Deal.CLIENT_STATUS]),
            source_type=random.choice([choice[0] for choice in Deal.SOURCE_TYPES]),
            payment_method=random.choice([choice[0] for choice in Deal.PAYMENT_METHOD_CHOICES]),
            deal_remarks=f"Rich testing deal created on {datetime.now()}",
            created_by=user,
        )
        return deal

    def create_related_data(self, all_deals, users):
        self.stdout.write(self.style.HTTP_INFO("  - Creating related data (Payments, Projects, Commissions, etc.)..."))
        
        # Ensure templates exist before creating notifications
        self.setup_notification_templates()

        for deal in all_deals:
            # Create Payments for deals that are not pending
            if deal.payment_status != 'pending':
                self.create_payments_for_deal(deal)

            # Create an Activity Log for each deal
            ActivityLog.objects.create(deal=deal, message=f"Deal created by {deal.created_by.username}.")

            # Create a Project for each deal in a targeted run
            if random.random() > 0.5 or len(users) == 1: # 50% chance, or 100% if targeted
                Project.objects.create(
                    name=f"Project for {deal.client.client_name}",
                    description=f"Rich testing deal project for deal {deal.deal_id}",
                    status=random.choice(['pending', 'in_progress', 'completed']),
                    created_by=deal.created_by,
                )

        # Create Commissions for users based on their deals
        for user in users:
            user_deals = [d for d in all_deals if d.created_by == user and d.payment_status in ['full_payment', 'partial_payment']]
            if user_deals:
                total_sales = sum(d.deal_value for d in user_deals)
                Commission.objects.create(
                    organization=user.organization,
                    user=user,
                    total_sales=total_sales,
                    start_date=datetime.now().date().replace(day=1),
                    end_date=datetime.now().date(),
                    created_by=user
                )

        # Create Notifications for some verified deals
        verified_deals = [d for d in all_deals if d.verification_status == 'verified']
        notification_sample_size = 20 if len(users) == 1 else 5
        
        verified_template = NotificationTemplate.objects.filter(notification_type='deal_verified').first()
        if verified_template:
            for deal in random.sample(verified_deals, min(len(verified_deals), notification_sample_size)):
                Notification.objects.create(
                    recipient=deal.created_by,
                    title=f"Deal Verified: {deal.deal_id}",
                    message=f"Rich testing deal {deal.deal_id} has been verified.",
                    notification_type='deal_verified'
                )
        self.stdout.write(self.style.SUCCESS(f"    - Created related data for {len(all_deals)} deals."))


    def create_payments_for_deal(self, deal):
        if deal.payment_status == 'full_payment':
            payment_count = 1
        else: # partial
            payment_count = random.randint(1, 3)

        for i in range(payment_count):
            amount_multiplier = 1 if deal.payment_status == 'full_payment' else (i + 1) * 0.25
            
            Payment.objects.create(
                deal=deal,
                payment_date=deal.deal_date + timedelta(days=random.randint(1, 10)),
                received_amount=deal.deal_value * Decimal(amount_multiplier),
                payment_type=deal.payment_method,
                payment_remarks=f"Payment for rich testing deal."
            ) 