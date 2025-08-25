import random
import re
import logging

from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.core.validators import validate_email as django_validate_email

def generate_otp(length: int = 6) -> str:
    """
    Generate a numeric one-time password (OTP).
    
    DEPRECATED: Use SecureOTPService.generate_otp() for enhanced security.
    This function is kept for backward compatibility.
    """
    import warnings
    warnings.warn(
        "generate_otp() is deprecated. Use SecureOTPService.generate_otp() for enhanced security.",
        DeprecationWarning,
        stacklevel=2
    )
    return ''.join(random.choices('0123456789', k=length))


def send_otp_email(email: str, otp: str) -> None:
    """
    Send an email containing a one-time password.
    
    DEPRECATED: Use SecureOTPService.send_otp_email() for enhanced security.
    This function is kept for backward compatibility.
    """
    import warnings
    warnings.warn(
        "send_otp_email() is deprecated. Use SecureOTPService.send_otp_email() for enhanced security.",
        DeprecationWarning,
        stacklevel=2
    )
    
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


def generate_secure_otp(user, purpose='login', request=None, length=6, expiry_minutes=5):
    """
    Generate a secure OTP using the enhanced OTP service.
    
    Args:
        user: User instance
        purpose: OTP purpose ('login', 'password_reset', etc.)
        request: HTTP request for security context
        length: OTP length (default: 6)
        expiry_minutes: Expiry time in minutes (default: 5)
        
    Returns:
        tuple: (OTPToken instance, plain OTP string)
    """
    from core_config.otp_service import secure_otp_service
    return secure_otp_service.generate_otp(user, purpose, request, length, expiry_minutes)


def verify_secure_otp(user, provided_otp, purpose='login', request=None):
    """
    Verify OTP using the enhanced OTP service.
    
    Args:
        user: User instance
        provided_otp: OTP provided by user
        purpose: OTP purpose
        request: HTTP request for security context
        
    Returns:
        tuple: (success: bool, message: str)
    """
    from core_config.otp_service import secure_otp_service
    return secure_otp_service.verify_otp(user, provided_otp, purpose, request)


def send_secure_otp_email(user, otp, purpose='login', otp_token=None):
    """
    Send OTP email using the enhanced OTP service.
    
    Args:
        user: User instance
        otp: OTP string
        purpose: OTP purpose
        otp_token: OTPToken instance for delivery tracking
        
    Returns:
        bool: True if sent successfully
    """
    from core_config.otp_service import secure_otp_service
    return secure_otp_service.send_otp_email(user, otp, purpose, otp_token)


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


def normalize_email(email: str) -> str:
    """
    Normalize email address by converting to lowercase and stripping whitespace.
    
    Args:
        email (str): Raw email address
        
    Returns:
        str: Normalized email address
        
    Raises:
        ValidationError: If email format is invalid
    """
    if not email:
        raise ValidationError("Email address is required.")
    
    # Strip whitespace and convert to lowercase
    normalized = email.strip().lower()
    
    # Validate email format using Django's built-in validator
    try:
        django_validate_email(normalized)
    except ValidationError:
        raise ValidationError("Please enter a valid email address.")
    
    return normalized


def validate_email_uniqueness(email: str, organization=None, exclude_user_id=None) -> str:
    """
    Validate email uniqueness with organization context and normalization.
    
    Args:
        email (str): Email address to validate
        organization: Organization instance for scoped validation (optional)
        exclude_user_id (int): User ID to exclude from duplicate check (for updates)
        
    Returns:
        str: Normalized email address
        
    Raises:
        ValidationError: If email is invalid or already exists
    """
    from .models import User  # Import here to avoid circular imports
    
    logger = logging.getLogger('django')
    
    # First normalize the email
    normalized_email = normalize_email(email)
    logger.info(f"[EMAIL_VALIDATION] Normalized email: {email} -> {normalized_email}")
    
    # Build query for duplicate checking
    duplicate_query = User.objects.filter(email=normalized_email)
    
    # Exclude current user if updating
    if exclude_user_id:
        duplicate_query = duplicate_query.exclude(id=exclude_user_id)
        logger.info(f"[EMAIL_VALIDATION] Excluding user ID {exclude_user_id} from duplicate check")
    
    # Check for duplicates
    if duplicate_query.exists():
        existing_user = duplicate_query.first()
        logger.warning(f"[EMAIL_VALIDATION] Duplicate email detected: {normalized_email} (existing user ID: {existing_user.id})")
        
        # Provide context-aware error messages
        if organization and existing_user.organization == organization:
            raise ValidationError(
                f"A user with the email address '{normalized_email}' already exists in your organization. "
                "Please use a different email address or contact your administrator if you believe this is an error."
            )
        elif existing_user.organization != organization:
            raise ValidationError(
                f"A user with the email address '{normalized_email}' already exists in another organization. "
                "Please use a different email address."
            )
        else:
            raise ValidationError(
                f"A user with the email address '{normalized_email}' already exists. "
                "Please use a different email address."
            )
    
    logger.info(f"[EMAIL_VALIDATION] Email validation successful: {normalized_email}")
    return normalized_email


def validate_user_email(email: str, organization=None, exclude_user_id=None) -> str:
    """
    Comprehensive email validation for user creation/update.
    
    This function combines email format validation, normalization, and uniqueness checking
    to provide a single point of validation for user email addresses.
    
    Args:
        email (str): Email address to validate
        organization: Organization instance for scoped validation (optional)
        exclude_user_id (int): User ID to exclude from duplicate check (for updates)
        
    Returns:
        str: Normalized and validated email address
        
    Raises:
        ValidationError: If email is invalid, improperly formatted, or already exists
    """
    logger = logging.getLogger('django')
    logger.info(f"[EMAIL_VALIDATION] Starting comprehensive email validation for: {email}")
    
    try:
        # Validate and normalize email
        validated_email = validate_email_uniqueness(email, organization, exclude_user_id)
        
        # Additional business logic validation can be added here
        # For example: domain restrictions, organization-specific rules, etc.
        
        logger.info(f"[EMAIL_VALIDATION] Comprehensive validation successful: {validated_email}")
        return validated_email
        
    except ValidationError as e:
        logger.error(f"[EMAIL_VALIDATION] Validation failed for {email}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"[EMAIL_VALIDATION] Unexpected error during validation: {str(e)}")
        raise ValidationError("An error occurred while validating the email address. Please try again.")