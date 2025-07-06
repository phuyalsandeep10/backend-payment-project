from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from .models import Deal, Payment, ActivityLog

# A simple cache to store the state of a deal before it's saved.
_pre_save_deal_cache = {}

@receiver(pre_save, sender=Deal)
def cache_deal_state(sender, instance, **kwargs):
    """
    Cache the deal's current state before it's saved.
    """
    if instance.pk:
        try:
            old_instance = Deal.objects.get(pk=instance.pk)
            _pre_save_deal_cache[instance.pk] = {
                'payment_status': old_instance.get_payment_status_display(),
                'verification_status': old_instance.get_verification_status_display(),
            }
        except Deal.DoesNotExist:
            pass # Instance is new, will be handled by the 'created' flag in post_save

##
##  logs the creation of deal
##
@receiver(post_save, sender=Deal)
def log_deal_activity(sender, instance, created, **kwargs):
    """
    Log creation and significant status changes for a Deal.
    """
    if created:
        ActivityLog.objects.create(deal=instance, message=f"Deal created for {instance.client.client_name}.")
    else:
        cached_state = _pre_save_deal_cache.get(instance.pk)
        if cached_state:
            new_status = instance.get_verification_status_display()
            if cached_state['verification_status'] != new_status:
                ActivityLog.objects.create(deal=instance, message=f"Deal verification_status updated to {new_status}")

##
##  logs the creation of deal
##
@receiver(post_save, sender=Payment)
def log_payment_activity(sender, instance, created, **kwargs):
    """
    Log creation and updates for a Payment.
    """
    deal = instance.deal
    if created:
        message = f"Payment of {instance.received_amount} received via {instance.get_payment_type_display()}."
        ActivityLog.objects.create(deal=deal, message=message)
    else:
        # This part is less common, but we can log updates if needed.
        # For now, focusing on creation is sufficient for a clean log.
        pass
        