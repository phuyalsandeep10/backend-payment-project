from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from apps.deals.models import Deal
from .utils import calculate_user_streak_for_date
from datetime import datetime

@receiver(post_delete, sender=Deal)
def update_streak_on_deal_delete(sender, instance, **kwargs):
    """
    Recalculate the user's streak for the day when a deal is deleted.
    """
    # Convert string to date if needed
    if isinstance(instance.deal_date, str):
        deal_date = datetime.strptime(instance.deal_date, '%Y-%m-%d').date()
    else:
        deal_date = instance.deal_date
    calculate_user_streak_for_date(instance.created_by, deal_date)

@receiver(post_save, sender=Deal)
def update_streak_on_deal_save(sender, instance, **kwargs):
    """
    Recalculate the user's streak for the day when a deal is created or updated.
    """
    # Convert string to date if needed
    if isinstance(instance.deal_date, str):
        deal_date = datetime.strptime(instance.deal_date, '%Y-%m-%d').date()
    else:
        deal_date = instance.deal_date
    calculate_user_streak_for_date(instance.created_by, deal_date) 