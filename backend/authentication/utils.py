import random

from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone

def generate_otp(length: int = 6) -> str:
    """Generate a numeric one-time password (OTP)."""
    return ''.join(random.choices('0123456789', k=length))


def send_otp_email(email: str, otp: str) -> None:
    """Send an email containing a one-time password."""
    subject = 'Your PRS verification code'
    message = (
        f'Your one-time verification code is: {otp}\n\n'
        'This code will expire in 5 minutes.'
    )
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)
        print(f"✅ OTP email sent successfully to {email}")
    except Exception as e:
        print(f"❌ Failed to send OTP email to {email}: {e}")
        # Fallback to console output
        print(f"📧 OTP for {email}: {otp}")


def send_temporary_password_email(email: str, temp_password: str) -> None:
    """Send an email with a temporary password for newly created admin users."""
    subject = 'Your PRS temporary password'
    message = (
        'You have been added as an administrator in the Payment Receiving System.\n\n'
        f'Temporary password: {temp_password}\n\n'
        'Use this password to log in and then change it immediately.'
    )
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=True)


def get_user_login_stats(user):
    """
    Get login statistics for a user.
    """
    return {
        'login_count': user.login_count,
        'last_login': user.last_login,
        'date_joined': user.date_joined,
        'days_since_joined': (timezone.now() - user.date_joined).days if user.date_joined else 0,
        'days_since_last_login': (timezone.now() - user.last_login).days if user.last_login else None,
    }

def increment_login_count(user):
    """
    Increment the login count for a user.
    """
    user.login_count += 1
    user.save(update_fields=['login_count'])
    return user.login_count 