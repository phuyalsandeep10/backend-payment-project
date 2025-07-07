import math
from django.utils import timezone
from django.db.models import Sum
from datetime import timedelta, date
from authentication.models import User
from deals.models import Deal
from .models import DailyStreakRecord
import logging

logger = logging.getLogger(__name__)

def calculate_streaks_for_user_login(user):
    """
    Calculate all missing streaks for a user from their last calculated date to today.
    This runs automatically when a salesperson logs in.
    """
    if not user.organization:
        return  # Not a salesperson
    
    today = timezone.now().date()
    
    # Find the last date we calculated streaks for this user
    last_record = DailyStreakRecord.objects.filter(
        user=user,
        streak_updated=True
    ).order_by('-date').first()
    
    if last_record:
        start_date = last_record.date + timedelta(days=1)
    else:
        # First time login - only calculate for today to avoid penalizing for past inactivity.
        # The user starts with the default streak and it's adjusted from today onwards.
        start_date = today
    
    # Calculate streaks for each missing day up to today
    current_date = start_date
    while current_date <= today:
        calculate_user_streak_for_date(user, current_date)
        current_date += timedelta(days=1)
    
    logger.info(f"Updated streaks for {user.username} from {start_date} to {today}")

def calculate_user_streak_for_date(user, target_date):
    """Calculate and update streak for a specific user on a specific date."""
    
    daily_record, created = DailyStreakRecord.objects.get_or_create(
        user=user,
        date=target_date,
        defaults={
            'deals_closed': 0,
            'total_deal_value': 0,
            'streak_updated': False
        }
    )

    if daily_record.streak_updated and not created:
        return

    # A streak is maintained if at least one deal worth >= $101 is closed
    # with a 'initial payment' or 'full_payment' status.
    successful_deals = Deal.objects.filter(
        created_by=user,
        deal_date=target_date,
        payment_status__in=['initial payment', 'full_payment'],
        deal_value__gte=101
    )

    deals_count = successful_deals.count()
    total_value = successful_deals.aggregate(
        total=Sum('deal_value')
    )['total'] or 0

    daily_record.deals_closed = deals_count
    daily_record.total_deal_value = total_value

    # Update streak with partial progress, capping at 5.0
    if deals_count > 0:
        user.streak = min(5.0, user.streak + 0.5)
    else:
        user.streak = max(0.0, user.streak - 0.5)

    daily_record.streak_updated = True
    daily_record.save()
    user.save(update_fields=['streak'])


STREAK_LEVELS = [
    (50, "Sales Legend"),
    (30, "Sales Master"),
    (20, "Sales Pro"),
    (10, "Rising Star"),
    (5, "Getting Started"),
    (1, "Beginner"),
]

def get_streak_level(streak):
    """Get text description of streak level based on the whole number of the streak."""
    streak_floor = math.floor(streak)
    for level, name in STREAK_LEVELS:
        if streak_floor >= level:
            return name
    return "New"

def get_days_until_next_level(streak):
    """Calculate days (0.5 streak increments) until next streak level"""
    levels = [1, 5, 10, 20, 30, 50]
    for level in levels:
        if streak < level:
            # Each day is a 0.5 increment
            return int((level - streak) * 2)
    return 0
