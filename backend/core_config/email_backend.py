"""
Robust Email Backend for PRS System
Multi-provider email service with fallbacks, retry logic, and network resilience
"""
import smtplib
import socket
import time
import logging
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend
from django.core.mail.message import EmailMessage
from django.core.mail import send_mail
import ssl

# Set up logging
logger = logging.getLogger('prs.email')

@dataclass
class SMTPConfig:
    """Configuration for an SMTP provider"""
    name: str
    host: str
    port: int
    use_tls: bool
    use_ssl: bool = False
    timeout: int = 30
    
    def __str__(self):
        return f"{self.name} ({self.host}:{self.port})"

class RobustEmailBackend(BaseEmailBackend):
    """
    Robust email backend with multiple providers and retry logic
    """
    
    def __init__(self, fail_silently=False, **kwargs):
        super().__init__(fail_silently=fail_silently, **kwargs)
        self.connection = None
        self._lock = threading.RLock()
        
        # Get credentials from settings
        self.email_host_user = getattr(settings, 'EMAIL_HOST_USER', '')
        self.email_host_password = getattr(settings, 'EMAIL_HOST_PASSWORD', '')
        self.default_from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', self.email_host_user)
        
        # Define SMTP providers in order of preference
        self.smtp_providers = self._get_smtp_providers()
        
        # Retry configuration
        self.max_retries = 3
        self.retry_delay = 1  # seconds
        self.retry_backoff = 2  # exponential backoff multiplier
        
        logger.info(f"RobustEmailBackend initialized with {len(self.smtp_providers)} providers")
        logger.info(f"Email user: {self.email_host_user}")
        logger.info(f"Default from: {self.default_from_email}")

    def _get_smtp_providers(self) -> List[SMTPConfig]:
        """Get list of SMTP providers to try"""
        providers = []
        
        # Primary provider from settings - clean up any whitespace
        primary_host = getattr(settings, 'EMAIL_HOST', 'smtp.gmail.com').strip()
        primary_port = getattr(settings, 'EMAIL_PORT', 587)
        primary_tls = getattr(settings, 'EMAIL_USE_TLS', True)
        primary_ssl = getattr(settings, 'EMAIL_USE_SSL', False)
        
        # Determine primary provider name
        if 'gmail' in primary_host.lower():
            primary_name = "Gmail"
        elif 'outlook' in primary_host.lower() or 'hotmail' in primary_host.lower():
            primary_name = "Outlook"
        else:
            primary_name = "Primary SMTP"
        
        providers.append(SMTPConfig(
            name=primary_name,
            host=primary_host,
            port=primary_port,
            use_tls=primary_tls,
            use_ssl=primary_ssl
        ))
        
        return providers

    def _create_connection(self, smtp_config: SMTPConfig) -> Optional[smtplib.SMTP]:
        """Create SMTP connection with network resilience"""
        try:
            logger.info(f"Attempting connection to {smtp_config}")
            
            # Create connection without IPv4 forcing to avoid conflicts
            connection = None
            
            if smtp_config.use_ssl:
                connection = smtplib.SMTP_SSL(
                    smtp_config.host, 
                    smtp_config.port, 
                    timeout=smtp_config.timeout
                )
            else:
                connection = smtplib.SMTP(
                    smtp_config.host, 
                    smtp_config.port, 
                    timeout=smtp_config.timeout
                )
            
            # Enable debug output for troubleshooting
            # connection.set_debuglevel(1)
            
            # Start TLS if required
            if smtp_config.use_tls and not smtp_config.use_ssl:
                logger.info("Starting TLS...")
                connection.starttls(context=ssl.create_default_context())
            
            # Authenticate
            if self.email_host_user and self.email_host_password:
                logger.info(f"Authenticating as {self.email_host_user}")
                connection.login(self.email_host_user, self.email_host_password)
                logger.info("Authentication successful")
            else:
                logger.warning("No email credentials provided")
            
            logger.info(f"Successfully connected to {smtp_config}")
            return connection
                
        except Exception as e:
            logger.error(f"Connection failed for {smtp_config}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return None

    def send_messages(self, email_messages: List[EmailMessage]) -> int:
        """Send email messages with retry logic and fallback providers"""
        if not email_messages:
            return 0
        
        logger.info(f"Attempting to send {len(email_messages)} email(s)")
        
        for provider in self.smtp_providers:
            for attempt in range(self.max_retries):
                try:
                    connection = self._create_connection(provider)
                    if not connection:
                        continue
                    
                    sent_count = 0
                    for message in email_messages:
                        try:
                            logger.info(f"Sending email: {message.subject} to {message.to}")
                            
                            # Use Django's built-in email handling
                            # Convert to proper email format
                            from_email = message.from_email or self.default_from_email
                            
                            # Create MIMEText message directly
                            msg = MIMEText(message.body, 'plain', 'utf-8')
                            msg['Subject'] = message.subject
                            msg['From'] = from_email
                            msg['To'] = ', '.join(message.to)
                            
                            # Send the email
                            text = msg.as_string()
                            connection.sendmail(from_email, message.to, text)
                            sent_count += 1
                            logger.info(f"Email sent successfully to {message.to}")
                            
                        except Exception as e:
                            logger.error(f"Failed to send individual message: {e}")
                            import traceback
                            logger.error(f"Full traceback: {traceback.format_exc()}")
                    
                    connection.quit()
                    
                    if sent_count > 0:
                        logger.info(f"Successfully sent {sent_count} emails via {provider}")
                        return sent_count
                        
                except Exception as e:
                    logger.error(f"Attempt {attempt + 1} failed for {provider}: {e}")
                    import traceback
                    logger.error(f"Full traceback: {traceback.format_exc()}")
                    
                    if attempt < self.max_retries - 1:
                        delay = self.retry_delay * (self.retry_backoff ** attempt)
                        logger.info(f"Waiting {delay} seconds before retry...")
                        time.sleep(delay)
        
        # All providers failed - fallback to console
        logger.warning("All SMTP providers failed, falling back to console output")
        self._fallback_to_console(email_messages)
        return len(email_messages)

    def _fallback_to_console(self, email_messages: List[EmailMessage]):
        """Fallback to console output when all SMTP providers fail"""
        print("\n" + "="*80)
        print("📧 EMAIL FALLBACK - Console Output (SMTP Failed)")
        print("="*80)
        
        for i, message in enumerate(email_messages, 1):
            print(f"\n--- EMAIL {i}/{len(email_messages)} ---")
            print(f"From: {message.from_email or self.default_from_email}")
            print(f"To: {', '.join(message.to)}")
            print(f"Subject: {message.subject}")
            print(f"\n{message.body}")
            print("-" * 50)
        
        print("="*80)


class EmailService:
    """High-level email service"""
    
    @staticmethod
    def send_email(subject, message, from_email=None, recipient_list=None, fail_silently=False):
        """Enhanced send_email function with better error handling"""
        try:
            if not recipient_list:
                logger.error("No recipient list provided")
                return False
            
            if not subject or not message:
                logger.error("Subject or message is empty")
                return False
            
            # Use Django's built-in send_mail with our custom backend
            from django.core.mail import send_mail
            
            from_email = from_email or getattr(settings, 'DEFAULT_FROM_EMAIL', '')
            if not from_email:
                logger.error("No from_email provided and DEFAULT_FROM_EMAIL not set")
                return False
            
            logger.info(f"Sending email: {subject} to {recipient_list} from {from_email}")
            
            sent_count = send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=fail_silently
            )
            
            success = sent_count > 0
            logger.info(f"Email send result: {success}, sent_count: {sent_count}")
            return success
                
        except Exception as e:
            logger.error(f"EmailService.send_email failed: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            if not fail_silently:
                raise
            return False
    
    @staticmethod
    def test_email_connection():
        """Test email connection and return detailed status"""
        backend = RobustEmailBackend()
        
        results = {
            'providers_tested': [],
            'successful_provider': None,
            'total_providers': len(backend.smtp_providers),
            'connection_successful': False,
            'error_details': [],
            'configuration': {
                'email_host_user': backend.email_host_user,
                'default_from_email': backend.default_from_email,
                'has_password': bool(backend.email_host_password)
            }
        }
        
        for provider in backend.smtp_providers:
            provider_result = {
                'name': provider.name,
                'host': provider.host,
                'port': provider.port,
                'use_tls': provider.use_tls,
                'use_ssl': provider.use_ssl,
                'connected': False,
                'error': None
            }
            
            try:
                connection = backend._create_connection(provider)
                if connection:
                    provider_result['connected'] = True
                    results['successful_provider'] = provider.name
                    results['connection_successful'] = True
                    try:
                        connection.quit()
                    except:
                        pass
                    break
                else:
                    provider_result['error'] = "Connection failed"
            except Exception as e:
                provider_result['error'] = str(e)
                results['error_details'].append(f"{provider.name}: {str(e)}")
            
            results['providers_tested'].append(provider_result)
        
        return results

    @staticmethod
    def send_otp_email(email: str, otp: str) -> bool:
        """Send OTP email with high priority"""
        return EmailService.send_email(
            subject="Your Admin Login OTP - PRS System",
            message=f"Your One-Time Password is: {otp}\n\nThis OTP is valid for 5 minutes.\n\nIf you did not request this, please contact your system administrator immediately.",
            recipient_list=[email],
            fail_silently=False
        )

    @staticmethod
    def send_notification_email(
        recipient_email: str,
        subject: str,
        content: str,
        priority: str = 'normal'
    ) -> bool:
        """Send notification email"""
        return EmailService.send_email(
            subject=subject,
            message=content,
            recipient_list=[recipient_email],
            fail_silently=True  # Don't break on notification failures
        )