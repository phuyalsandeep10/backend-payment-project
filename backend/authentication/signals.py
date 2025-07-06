from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import UserProfile
from django.conf import settings

User = settings.AUTH_USER_MODEL

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Create a user profile when a new user is created.
    """
    if created:
        UserProfile.objects.get_or_create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Save the user profile when the user is saved.
    """
    if hasattr(instance, 'profile'):
        instance.profile.save()
    else:
        # This handles cases where the profile might not have been created yet,
        # for example, for existing users created before this signal was in place.
        UserProfile.objects.get_or_create(user=instance) 