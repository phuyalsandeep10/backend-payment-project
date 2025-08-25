"""
Management command to check password expiration and send notifications
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from apps.authentication.models import User, PasswordExpiration
from authentication.password_policy import PasswordPolicy
from datetime import timedelta
import logging

# Security logger
security_logger = logging.getLogger('security')

class Command(BaseCommand):
    help = 'Check password expiration and send notifications to users'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without actually sending emails'
        )
        parser.add_argument(
            '--organization',
            type=str,
            help='Check only users from specific organization'
        )
        parser.add_argument(
            '--send-warnings',
            action='store_true',
            help='Send warning notifications for passwords expiring soon'
        )
        parser.add_argument(
            '--mark-expired',
            action='store_true',
            help='Mark expired passwords and force password change'
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        organization_name = options['organization']
        send_warnings = options['send_warnings']
        mark_expired = options['mark_expired']

        self.stdout.write(
            self.style.SUCCESS('Starting password expiration check...')
        )

        # Filter users by organization if specified
        users_query = User.objects.filter(is_active=True)
        if organization_name:
            try:
                from apps.organization.models import Organization
                organization = Organization.objects.get(name=organization_name)
                users_query = users_query.filter(organization=organization)
                self.stdout.write(f"Checking users in organization: {organization_name}")
            except Organization.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f"Organization '{organization_name}' not found")
                )
                return

        users = users_query.select_related('organization')
        
        warning_count = 0
        expired_count = 0
        
        for user in users:
            try:
                # Check password expiration status
                expiration_info = PasswordPolicy.check_password_expiration(user)
                
                if expiration_info['expired']:
                    expired_count += 1
                    if mark_expired:
                        self._handle_expired_password(user, dry_run)
                    else:
                        self.stdout.write(
                            f"EXPIRED: {user.email} - expired {abs(expiration_info['days_until_expiration'])} days ago"
                        )
                
                elif expiration_info['expires_soon']:
                    warning_count += 1
                    if send_warnings:
                        self._send_expiration_warning(user, expiration_info, dry_run)
                    else:
                        self.stdout.write(
                            f"WARNING: {user.email} - expires in {expiration_info['days_until_expiration']} days"
                        )
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Error processing user {user.email}: {str(e)}")
                )
                security_logger.error(f"Password expiration check error for {user.email}: {str(e)}")

        # Summary
        self.stdout.write(
            self.style.SUCCESS(
                f"\nPassword Expiration Check Complete:\n"
                f"  Users checked: {users.count()}\n"
                f"  Passwords expiring soon: {warning_count}\n"
                f"  Passwords expired: {expired_count}\n"
                f"  Dry run: {'Yes' if dry_run else 'No'}"
            )
        )

    def _send_expiration_warning(self, user, expiration_info, dry_run):
        """Send password expiration warning email"""
        days_until_expiration = expiration_info['days_until_expiration']
        
        subject = "Password Expiration Warning - PRS System"
        message = f"""
Dear {user.first_name or user.username},

Your password for the PRS (Payment Receiving System) will expire in {days_until_expiration} day(s).

Expiration Date: {expiration_info['expiration_date'].strftime('%Y-%m-%d')}

To avoid being locked out of your account, please log in and change your password before it expires.

If you need assistance, please contact your Organization Administrator.

Best regards,
PRS System Security Team
        """
        
        if dry_run:
            self.stdout.write(f"[DRY RUN] Would send warning email to {user.email}")
        else:
            try:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                
                # Update notification tracking
                password_expiration, created = PasswordExpiration.objects.get_or_create(
                    user=user
                )
                password_expiration.warning_sent_count += 1
                password_expiration.expiration_notified_at = timezone.now()
                password_expiration.save()
                
                self.stdout.write(f"Warning email sent to {user.email}")
                security_logger.info(f"Password expiration warning sent to {user.email}")
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Failed to send warning email to {user.email}: {str(e)}")
                )
                security_logger.error(f"Failed to send password expiration warning to {user.email}: {str(e)}")

    def _handle_expired_password(self, user, dry_run):
        """Handle expired password - force password change"""
        if dry_run:
            self.stdout.write(f"[DRY RUN] Would mark password as expired for {user.email}")
        else:
            try:
                # Mark user as needing password change
                user.must_change_password = True
                user.save(update_fields=['must_change_password'])
                
                # Update expiration tracking
                password_expiration, created = PasswordExpiration.objects.get_or_create(
                    user=user
                )
                password_expiration.is_expired = True
                password_expiration.save()
                
                # Send expired password notification
                self._send_expired_password_notification(user)
                
                self.stdout.write(f"Marked password as expired for {user.email}")
                security_logger.info(f"Password marked as expired for {user.email}")
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Failed to handle expired password for {user.email}: {str(e)}")
                )
                security_logger.error(f"Failed to handle expired password for {user.email}: {str(e)}")

    def _send_expired_password_notification(self, user):
        """Send password expired notification"""
        subject = "Password Expired - Immediate Action Required"
        message = f"""
Dear {user.first_name or user.username},

Your password for the PRS (Payment Receiving System) has expired and must be changed immediately.

You will be required to change your password the next time you log in.

If you need assistance, please contact your Organization Administrator.

Best regards,
PRS System Security Team
        """
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            
            self.stdout.write(f"Expired password notification sent to {user.email}")
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Failed to send expired notification to {user.email}: {str(e)}")
            )
            security_logger.error(f"Failed to send expired password notification to {user.email}: {str(e)}")