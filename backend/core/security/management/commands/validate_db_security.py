"""
Django management command to validate database security
Usage: python manage.py validate_db_security
"""
from django.core.management.base import BaseCommand
from core_config.database_security import DatabaseSecurityValidator


class Command(BaseCommand):
    """
    Django management command to validate database security
    """
    help = 'Validate database connection security settings and configuration'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--detailed',
            action='store_true',
            help='Show detailed security analysis',
        )
        parser.add_argument(
            '--fix-warnings',
            action='store_true',
            help='Attempt to fix security warnings automatically',
        )
    
    def handle(self, *args, **options):
        self.stdout.write("🔒 Database Security Validation")
        self.stdout.write("=" * 50)
        
        validator = DatabaseSecurityValidator()
        success = validator.validate_connection_security()
        
        if options['detailed']:
            self._show_detailed_report(validator)
        
        if options['fix_warnings'] and validator.warnings:
            self._attempt_fixes(validator.warnings)
        
        if success:
            self.stdout.write(
                self.style.SUCCESS("\n✅ Database security validation PASSED!")
            )
            self.stdout.write("🔒 Database connections are properly secured.")
        else:
            self.stdout.write(
                self.style.ERROR("\n❌ Database security validation FAILED!")
            )
            self.stdout.write("⚠️ Please review and fix security issues before production deployment.")
            return 1
        
        return 0
    
    def _show_detailed_report(self, validator):
        """Show detailed security report"""
        self.stdout.write("\n📊 Detailed Security Analysis:")
        self.stdout.write("-" * 30)
        
        if validator.security_checks:
            self.stdout.write(self.style.SUCCESS("\n✅ Security Checks Passed:"))
            for check in validator.security_checks:
                self.stdout.write(f"  • {check}")
        
        if validator.warnings:
            self.stdout.write(self.style.WARNING("\n⚠️ Security Warnings:"))
            for warning in validator.warnings:
                self.stdout.write(f"  • {warning}")
        
        if validator.errors:
            self.stdout.write(self.style.ERROR("\n❌ Security Errors:"))
            for error in validator.errors:
                self.stdout.write(f"  • {error}")
    
    def _attempt_fixes(self, warnings):
        """Attempt to fix common security warnings"""
        self.stdout.write(self.style.WARNING("\n🔧 Attempting to fix security warnings..."))
        
        fixes_applied = []
        
        for warning in warnings:
            if "SSL is disabled" in warning:
                fixes_applied.append("Recommend setting DB_SSLMODE=prefer in environment")
            elif "No connection timeout" in warning:
                fixes_applied.append("Recommend adding connect_timeout to database OPTIONS")
            elif "Default transaction isolation" in warning:
                fixes_applied.append("Recommend setting transaction isolation to serializable")
        
        if fixes_applied:
            self.stdout.write("💡 Recommended fixes:")
            for fix in fixes_applied:
                self.stdout.write(f"  • {fix}")
        else:
            self.stdout.write("ℹ️ No automatic fixes available for current warnings.")