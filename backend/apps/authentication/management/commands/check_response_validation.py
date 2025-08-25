"""
Management command to check response validation decorator coverage.
"""

from django.core.management.base import BaseCommand
from django.conf import settings
import os
import sys
import importlib.util

class Command(BaseCommand):
    help = 'Check response validation decorator coverage on authentication views'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Automatically apply missing decorators (dry run by default)',
        )
        parser.add_argument(
            '--report',
            action='store_true',
            help='Generate detailed coverage report',
        )
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Checking Response Validation Decorator Coverage')
        )
        self.stdout.write('=' * 60)
        
        # Import and run the verification script
        try:
            # Get the path to the verification script
            auth_dir = os.path.join(settings.BASE_DIR, 'authentication')
            verify_script_path = os.path.join(auth_dir, 'verify_response_decorators.py')
            
            if not os.path.exists(verify_script_path):
                self.stdout.write(
                    self.style.ERROR(f'Verification script not found: {verify_script_path}')
                )
                return
            
            # Import the verification module
            spec = importlib.util.spec_from_file_location("verify_decorators", verify_script_path)
            verify_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verify_module)
            
            # Run the verification
            success = verify_module.main()
            
            if success:
                self.stdout.write(
                    self.style.SUCCESS('\n✅ All critical authentication views have response validation decorators!')
                )
            else:
                self.stdout.write(
                    self.style.ERROR('\n❌ Some views are missing response validation decorators.')
                )
            
            if options['report']:
                self.generate_detailed_report()
            
            if options['fix'] and not success:
                self.stdout.write(
                    self.style.WARNING('\n🔧 Fix mode is not implemented yet. Please apply decorators manually.')
                )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error running verification: {str(e)}')
            )
    
    def generate_detailed_report(self):
        """Generate a detailed coverage report."""
        self.stdout.write('\n📊 Detailed Coverage Report')
        self.stdout.write('-' * 30)
        
        try:
            from authentication.response_validation_logger import response_validation_logger
            report = response_validation_logger.generate_validation_report()
            
            self.stdout.write(f"Report generated: {report['timestamp']}")
            self.stdout.write(f"Status: {report['status']}")
            
            self.stdout.write('\nDecorators available:')
            for decorator in report['decorators_applied']:
                self.stdout.write(f"  ✓ {decorator}")
            
            self.stdout.write('\nCritical endpoints covered:')
            for endpoint in report['critical_endpoints_covered']:
                self.stdout.write(f"  ✓ {endpoint}")
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error generating report: {str(e)}')
            )