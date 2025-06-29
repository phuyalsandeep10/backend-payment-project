from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from .models import Deal, Payment, logactivity


##
##  logs any changes in deals fields into activity log
##
@receiver(pre_save, sender=Deal)
def log_deals_field_changes(sender, instance, **kwargs):
    if not instance.pk:
        return  # Object is new, so there's nothing to compare to.

    try:
        old = Deal.objects.get(pk=instance.pk)
    except Deal.DoesNotExist:
        return # Should not happen if instance.pk is set, but as a safeguard.

    for field in instance._meta.fields:
        name = field.name
        if name in ["id", "created_at", "updated_at"]:  # Ignore certain fields
            continue
            
        old_value = getattr(old, name)
        new_value = getattr(instance, name)
        
        if old_value != new_value:
            logactivity(instance, f"Field '{field.verbose_name}' changed from '{old_value}' to '{new_value}'")


##
##  logs the creation of deal
##
@receiver(post_save, sender=Payment)
def log_payment_activity(sender, instance, created, **kwargs):
    deal = instance.deal
    if created:
        logactivity(deal, f"Payment of {instance.received_amount} received on {instance.payment_date}")
    else:
        logactivity(deal, f"Payment updated to {instance.received_amount} on {instance.payment_date}")
        