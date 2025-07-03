from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
from django.db.models import Sum
from deals.models import Deal
from .models import DailyStreakRecord

@receiver(post_save, sender=Deal)
def update_streak_on_deal_change(sender, instance, created, **kwargs):
    """Update streak when a deal is created or updated."""
    if instance.deal_status == 'verified':
        update_user_streak_for_date(instance.created_by, instance.deal_date)

@receiver(post_delete, sender=Deal)
def update_streak_on_deal_delete(sender, instance, **kwargs):
    """Update streak when a deal is deleted."""
    if instance.deal_status == 'verified':
        update_user_streak_for_date(instance.created_by, instance.deal_date)

def update_user_streak_for_date(user, date):
    """Recalculate and update user's streak for a specific date."""
    
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

    # Calculate current performance for this date
    deals_today = Deal.objects.filter(
        created_by=user,
        deal_date=date,
        deal_status='verified'
    )

    deals_count = deals_today.count()
    total_value = deals_today.aggregate(
        total=Sum('deal_value')
    )['total'] or 0

    # Update daily record
    old_deals_count = daily_record.deals_closed
    old_total_value = daily_record.total_deal_value
    
    daily_record.deals_closed = deals_count
    daily_record.total_deal_value = total_value

    # Only update streak if the performance evaluation changed
    old_performance = evaluate_performance(old_deals_count, old_total_value)
    new_performance = evaluate_performance(deals_count, total_value)

    if old_performance != new_performance or not daily_record.streak_updated:
        # Reverse old streak effect (if any)
        if daily_record.streak_updated:
            if old_performance == 'increase':
                user.streak = max(0, user.streak - 1)
            elif old_performance == 'decrease':
                user.streak = user.streak * 2  # Reverse the halving

        # Apply new streak effect
        if new_performance == 'increase':
            user.streak += 1
        elif new_performance == 'decrease':
            user.streak = max(0, user.streak // 2)

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