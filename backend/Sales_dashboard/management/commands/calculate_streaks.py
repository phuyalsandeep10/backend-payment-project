from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Sum, Q
from datetime import timedelta
from authentication.models import User
from deals.models import Deal
from Sales_dashboard.models import DailyStreakRecord

class Command(BaseCommand):
    help = 'Calculate and update streaks for all salespeople based on daily performance'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Date to calculate streaks for (YYYY-MM-DD). Defaults to yesterday.',
        )

    def handle(self, *args, **options):
        # Determine the date to process
        if options['date']:
            target_date = timezone.datetime.strptime(options['date'], '%Y-%m-%d').date()
        else:
            target_date = (timezone.now() - timedelta(days=1)).date()

        self.stdout.write(f'Calculating streaks for {target_date}...')

        # Get all users who are salespeople (have an organization)
        salespeople = User.objects.filter(organization__isnull=False)

        for user in salespeople:
            self.calculate_user_streak(user, target_date)

        self.stdout.write(
            self.style.SUCCESS(f'Successfully calculated streaks for {salespeople.count()} salespeople')
        )

    def calculate_user_streak(self, user, date):
        """Calculate and update streak for a specific user on a specific date."""
        
        # Get or create daily record
        daily_record, created = DailyStreakRecord.objects.get_or_create(
            user=user,
            date=date,
            defaults={
                'deals_closed': 0,
                'total_deal_value': 0,
                'streak_updated': False
            }
        )

        # If already processed, skip
        if daily_record.streak_updated and not created:
            return

        # Calculate daily performance
        deals_today = Deal.objects.filter(
            created_by=user,
            deal_date=date,
            deal_status='verified'  # Only count verified deals
        )

        deals_count = deals_today.count()
        total_value = deals_today.aggregate(
            total=Sum('deal_value')
        )['total'] or 0

        # Update daily record
        daily_record.deals_closed = deals_count
        daily_record.total_deal_value = total_value

        # Calculate streak update
        streak_performance = self.evaluate_performance(deals_count, total_value)
        
        if streak_performance == 'increase':
            user.streak += 1
        elif streak_performance == 'decrease':
            user.streak = max(0, user.streak // 2)  # Decrease by half, minimum 0
        # 'maintain' keeps streak unchanged

        # Save updates
        daily_record.streak_updated = True
        daily_record.save()
        user.save()

        self.stdout.write(
            f'  {user.username}: {deals_count} deals, ${total_value}, streak: {user.streak} ({streak_performance})'
        )

    def evaluate_performance(self, deals_count, total_value):
        """
        Evaluate performance and return streak action.
        
        Rules:
        - Increase streak: At least 1 deal with value >= 101
        - Decrease streak: No deals OR all deals < 101
        - Maintain streak: Mixed performance (some good deals, some bad)
        """
        if deals_count == 0:
            return 'decrease'  # No deals closed
        
        if total_value < 101:
            return 'decrease'  # All deals are too small
        
        return 'increase'  # At least one good deal 