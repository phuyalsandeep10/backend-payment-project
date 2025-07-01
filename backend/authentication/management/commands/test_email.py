"""
Django Management Command: Test Email System
Test SMTP configuration and send test emails
"""
from django.core.management.base import BaseCommand
from django.conf import settings
from core_config.email_backend import EmailService
import json

class Command(BaseCommand):
    help = 'Test email configuration and send test emails'

    def add_arguments(self, parser):
        parser.add_argument(
            '--test-connection',
            action='store_true',
            help='Test SMTP connection only',
        )
        parser.add_argument(
            '--send-test',
            type=str,
            help='Send test email to specified address',
        )
        parser.add_argument(
            '--send-otp',
            type=str,
            help='Send test OTP email to specified address',
        )
        parser.add_argument(
            '--check-config',
            action='store_true',
            help='Check email configuration settings',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('📧 EMAIL SYSTEM TEST'))
        self.stdout.write('=' * 50)
        
        if options['check_config']:
            self.check_configuration()
        
        if options['test_connection']:
            self.test_connection()
        
        if options['send_test']:
            self.send_test_email(options['send_test'])
            
        if options['send_otp']:
            self.send_otp_email(options['send_otp'])
        
        # If no specific option, run all tests
        if not any([options['check_config'], options['test_connection'], 
                   options['send_test'], options['send_otp']]):
            self.check_configuration()
            self.test_connection()

    def check_configuration(self):
        """Check email configuration settings"""
        self.stdout.write('\n🔧 EMAIL CONFIGURATION')
        self.stdout.write('-' * 30)
        
        config = {
            'EMAIL_BACKEND': getattr(settings, 'EMAIL_BACKEND', 'Not set'),
            'EMAIL_HOST': getattr(settings, 'EMAIL_HOST', 'Not set'),
            'EMAIL_PORT': getattr(settings, 'EMAIL_PORT', 'Not set'),
            'EMAIL_USE_TLS': getattr(settings, 'EMAIL_USE_TLS', 'Not set'),
            'EMAIL_USE_SSL': getattr(settings, 'EMAIL_USE_SSL', 'Not set'),
            'EMAIL_HOST_USER': getattr(settings, 'EMAIL_HOST_USER', 'Not set'),
            'EMAIL_HOST_PASSWORD': '***SET***' if getattr(settings, 'EMAIL_HOST_PASSWORD', '') else 'NOT SET',
            'DEFAULT_FROM_EMAIL': getattr(settings, 'DEFAULT_FROM_EMAIL', 'Not set'),
            'SUPER_ADMIN_OTP_EMAIL': getattr(settings, 'SUPER_ADMIN_OTP_EMAIL', 'Not set'),
        }
        
        for key, value in config.items():
            if 'PASSWORD' in key:
                color = self.style.SUCCESS if value == '***SET***' else self.style.ERROR
            elif value == 'Not set' or value == 'NOT SET':
                color = self.style.ERROR
            else:
                color = self.style.SUCCESS
            
            self.stdout.write(f"  {key}: {color(value)}")
        
        # Check for common issues
        self.stdout.write('\n🔍 CONFIGURATION ANALYSIS')
        self.stdout.write('-' * 30)
        
        issues = []
        
        if not getattr(settings, 'EMAIL_HOST_USER', ''):
            issues.append("EMAIL_HOST_USER is not set")
        
        if not getattr(settings, 'EMAIL_HOST_PASSWORD', ''):
            issues.append("EMAIL_HOST_PASSWORD is not set")
        
        if not getattr(settings, 'DEFAULT_FROM_EMAIL', ''):
            issues.append("DEFAULT_FROM_EMAIL is not set")
        
        email_host = getattr(settings, 'EMAIL_HOST', '')
        if 'gmail' in email_host.lower():
            self.stdout.write("  📌 Gmail detected: Make sure you're using an 'App Password', not your regular password")
            self.stdout.write("     Generate one at: https://myaccount.google.com/apppasswords")
        
        if issues:
            self.stdout.write("  ❌ Issues found:")
            for issue in issues:
                self.stdout.write(f"     - {self.style.ERROR(issue)}")
        else:
            self.stdout.write("  ✅ Configuration looks good!")

    def test_connection(self):
        """Test SMTP connection"""
        self.stdout.write('\n🔗 TESTING SMTP CONNECTION')
        self.stdout.write('-' * 30)
        
        try:
            result = EmailService.test_email_connection()
            
            self.stdout.write(f"  Total providers: {result['total_providers']}")
            self.stdout.write(f"  Connection successful: {self.style.SUCCESS('YES') if result['connection_successful'] else self.style.ERROR('NO')}")
            
            if result['successful_provider']:
                self.stdout.write(f"  Successful provider: {self.style.SUCCESS(result['successful_provider'])}")
            
            self.stdout.write('\n  📊 Provider Details:')
            for provider in result['providers_tested']:
                status_color = self.style.SUCCESS if provider['connected'] else self.style.ERROR
                status_text = '✅ Connected' if provider['connected'] else '❌ Failed'
                
                self.stdout.write(f"    {provider['name']} ({provider['host']}:{provider['port']}): {status_color(status_text)}")
                if provider['error']:
                    self.stdout.write(f"      Error: {self.style.ERROR(provider['error'])}")
            
            if result['error_details']:
                self.stdout.write('\n  🚨 Error Details:')
                for error in result['error_details']:
                    self.stdout.write(f"    {self.style.ERROR(error)}")
                    
        except Exception as e:
            self.stdout.write(f"  {self.style.ERROR('Connection test failed:')} {str(e)}")

    def send_test_email(self, recipient):
        """Send a test email"""
        self.stdout.write(f'\n📮 SENDING TEST EMAIL TO: {recipient}')
        self.stdout.write('-' * 40)
        
        try:
            success = EmailService.send_email(
                subject="PRS System - Test Email",
                message="This is a test email from the PRS system.\n\nIf you received this, your email configuration is working correctly!",
                recipient_list=[recipient],
                fail_silently=False
            )
            
            if success:
                self.stdout.write(f"  {self.style.SUCCESS('✅ Test email sent successfully!')}")
            else:
                self.stdout.write(f"  {self.style.ERROR('❌ Test email failed to send')}")
                
        except Exception as e:
            self.stdout.write(f"  {self.style.ERROR('Test email failed:')} {str(e)}")

    def send_otp_email(self, recipient):
        """Send a test OTP email"""
        self.stdout.write(f'\n🔐 SENDING TEST OTP EMAIL TO: {recipient}')
        self.stdout.write('-' * 40)
        
        try:
            test_otp = "12345678"
            success = EmailService.send_otp_email(recipient, test_otp)
            
            if success:
                self.stdout.write(f"  {self.style.SUCCESS('✅ OTP email sent successfully!')}")
                self.stdout.write(f"  Test OTP: {self.style.WARNING(test_otp)}")
            else:
                self.stdout.write(f"  {self.style.ERROR('❌ OTP email failed to send')}")
                
        except Exception as e:
            self.stdout.write(f"  {self.style.ERROR('OTP email failed:')} {str(e)}") 