import random

from django.core.mail import send_mail
from django.conf import settings

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
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=True)


def send_temporary_password_email(email: str, temp_password: str) -> None:
    """Send an email with a temporary password for newly created admin users."""
    subject = 'Your PRS temporary password'
    message = (
        'You have been added as an administrator in the Payment Receiving System.\n\n'
        f'Temporary password: {temp_password}\n\n'
        'Use this password to log in and then change it immediately.'
    )
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=True) 