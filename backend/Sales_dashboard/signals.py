from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from deals.models import Deal
from .utils import calculate_user_streak_for_date

@receiver(post_delete, sender=Deal)
def update_streak_on_deal_delete(sender, instance, **kwargs):
    """
    Recalculate the user's streak for the day when a deal is deleted.
    """
    calculate_user_streak_for_date(instance.created_by, instance.deal_date)

@receiver(post_save, sender=Deal)
def update_streak_on_deal_save(sender, instance, **kwargs):
    """
    Recalculate the user's streak for the day when a deal is created or updated.
    """
    calculate_user_streak_for_date(instance.created_by, instance.deal_date) 