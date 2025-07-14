from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver, Signal
from django.apps import apps
from notifications.models import Notification
from django.contrib.contenttypes.models import ContentType
import logging

# A simple cache to store the state of a deal before it's saved.
_pre_save_deal_cache = {}

@receiver(pre_save, sender='deals.Deal')
def cache_deal_state(sender, instance, **kwargs):
    """
    Cache the deal's current state before it's saved.
    """
    Deal = apps.get_model('deals', 'Deal')
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
@receiver(post_save, sender='deals.Deal')
def log_deal_activity(sender, instance, created, **kwargs):
    """
    Log creation and significant status changes for a Deal.
    """
    ActivityLog = apps.get_model('deals', 'ActivityLog')
    if created:
        ActivityLog.objects.create(deal=instance, message=f"Deal created for {instance.client.client_name}.")
        
        # Create initial payment record for the deal
        Payment = apps.get_model('deals', 'Payment')
        try:
            # Create an initial payment record based on deal's payment status
            initial_payment = Payment.objects.create(
                deal=instance,
                payment_date=instance.deal_date,  # Use deal date as payment date
                received_amount=instance.deal_value,  # Use full deal value
                payment_type=instance.payment_method,  # Use deal's payment method
                payment_remarks=f"Initial payment for deal {instance.deal_id}",
                cheque_number="",  # Empty for initial payment
            )
            # Log the initial payment creation
            ActivityLog.objects.create(
                deal=instance, 
                message=f"Initial payment of {instance.deal_value} created for deal {instance.deal_id}."
            )
        except Exception as e:
            # Log error but don't fail the deal creation
            logging.error(f"Failed to create initial payment for deal {instance.deal_id}: {e}")
            # Don't raise the exception to avoid breaking deal creation
    else:
        cached_state = _pre_save_deal_cache.get(instance.pk)
        if cached_state:
            new_status = instance.get_verification_status_display()
            if cached_state['verification_status'] != new_status:
                ActivityLog.objects.create(deal=instance, message=f"Deal verification_status updated to {new_status}")

##
##  logs the creation of deal
##
@receiver(post_save, sender='deals.Payment')
def log_payment_activity(sender, instance, created, **kwargs):
    """
    Log creation and updates for a Payment.
    """
    ActivityLog = apps.get_model('deals', 'ActivityLog')
    deal = instance.deal
    if created:
        message = f"Payment of {instance.received_amount} received via {instance.get_payment_type_display()}."
        ActivityLog.objects.create(deal=deal, message=message)
    else:
        # This part is less common, but we can log updates if needed.
        # For now, focusing on creation is sufficient for a clean log.
        pass

@receiver(post_save, sender='deals.Payment')
def create_invoice_on_payment(sender,instance,created,**kwargs):
    PaymentInvoice = apps.get_model('deals', 'PaymentInvoice')
    if created:
        PaymentInvoice.objects.create(
            payment=instance,
            deal=instance.deal,
        )

@receiver(post_save, sender='deals.PaymentApproval')
def update_invoice_status_on_approval(sender, instance, created, **kwargs):
    if getattr(instance, '_skip_signal', False):
        return
        
    PaymentInvoice = apps.get_model('deals', 'PaymentInvoice')
    if created:
        try:
            invoice = PaymentInvoice.objects.get(payment=instance.payment)
            if instance.failure_remarks:
                invoice.invoice_status = 'rejected'
            else:
                invoice.invoice_status = 'verified'
            invoice.save(user=instance.approved_by)
        except PaymentInvoice.DoesNotExist:
            pass