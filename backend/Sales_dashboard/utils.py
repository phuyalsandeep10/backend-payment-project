from django.utils import timezone
from django.db.models import Sum
from datetime import timedelta, date
from authentication.models import User
from deals.models import Deal
from .models import DailyStreakRecord

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
        # First time login - start from 30 days ago or first deal date
        first_deal = Deal.objects.filter(created_by=user).order_by('deal_date').first()
        if first_deal:
            start_date = max(first_deal.deal_date, today - timedelta(days=30))
        else:
            start_date = today
    
    # Calculate streaks for each missing day up to today
    current_date = start_date
    while current_date <= today:
        calculate_user_streak_for_date(user, current_date)
        current_date += timedelta(days=1)
    
    print(f"Updated streaks for {user.username} from {start_date} to {today}")

def calculate_user_streak_for_date(user, target_date):
    """Calculate and update streak for a specific user on a specific date."""
    
    # Get or create daily record
    daily_record, created = DailyStreakRecord.objects.get_or_create(
        user=user,
        date=target_date,
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
        deal_date=target_date,
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
    streak_performance = evaluate_performance(deals_count, total_value)
    
    if streak_performance == 'increase':
        user.streak += 1
    elif streak_performance == 'decrease':
        user.streak = max(0, user.streak // 2)  # Decrease by half, minimum 0
    # 'maintain' keeps streak unchanged

    # Save updates
    daily_record.streak_updated = True
    daily_record.save()
    user.save()

def evaluate_performance(deals_count, total_value):
    """
    Evaluate performance and return streak action.
    
    Rules:
    - Increase streak: At least 1 deal with total value >= 101
    - Decrease streak: No deals OR total value < 101
    """
    if deals_count == 0:
        return 'decrease'  # No deals closed
    
    if total_value < 101:
        return 'decrease'  # Total value too small
    
    return 'increase'  # Good performance

def get_streak_emoji(streak):
    """Convert streak number to star emoji representation."""
    if streak == 0:
        return "☆☆☆☆☆"  # Empty stars
    elif streak <= 5:
        return "★" * streak + "☆" * (5 - streak)
    else:
        return "★" * 5 + f" (+{streak - 5})"  # 5 stars plus extra count 