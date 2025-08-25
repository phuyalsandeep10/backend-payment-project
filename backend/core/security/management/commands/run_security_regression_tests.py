"""
Django management command for running security regression tests
Task 6.1.2: Security regression testing command integration
"""

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
import os
import sys
import json
from datetime import datetime

# Add tests directory to Python path
tests_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))), 'tests')
if tests_dir not in sys.path:
    sys.path.append(tests_dir)

try:
    from security.security_regression_framework import SecurityRegressionTester, SecurityRegressionDatabase, SecurityFixture
except ImportError as e:
    SecurityRegressionTester = None
    SecurityRegressionDatabase = None
    SecurityFixture = None
    import_error = str(e)


class Command(BaseCommand):
    help = 'Run security regression tests to detect security vulnerabilities that may have been reintroduced'

    def add_arguments(self, parser):
        parser.add_argument(
            '--vulnerability-types',
            nargs='*',
            choices=[
                'sql_injection', 'xss', 'csrf', 'authentication', 'file_upload',
                'access_control', 'session_management', 'all'
            ],
            default=['all'],
            help='Vulnerability types to test for regressions (default: all)'
        )
        
        parser.add_argument(
            '--add-fixture',
            action='store_true',
            help='Add a new security fixture for regression testing'
        )
        
        parser.add_argument(
            '--fixture-name',
            type=str,
            help='Name for the new security fixture'
        )
        
        parser.add_argument(
            '--fixture-type',
            type=str,
            choices=[
                'sql_injection', 'xss', 'csrf', 'authentication', 'file_upload',
                'access_control', 'session_management'
            ],
            help='Type of vulnerability for the new fixture'
        )
        
        parser.add_argument(
            '--severity',
            type=str,
            choices=['critical', 'high', 'medium', 'low'],
            default='medium',
            help='Severity level for new fixture (default: medium)'
        )
        
        parser.add_argument(
            '--list-fixtures',
            action='store_true',
            help='List all existing security fixtures'
        )
        
        parser.add_argument(
            '--history',
            type=str,
            help='Show regression test history for a specific fixture ID'
        )
        
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days of history to show (default: 30)'
        )
        
        parser.add_argument(
            '--output',
            type=str,
            help='Output file path for regression test report (JSON format)'
        )
        
        parser.add_argument(
            '--db-path',
            type=str,
            help='Path to regression test database file'
        )
        
        parser.add_argument(
            '--fail-on-regression',
            action='store_true',
            help='Exit with error code if any regressions are detected'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

    def handle(self, *args, **options):
        if SecurityRegressionTester is None:
            raise CommandError(f'Could not import SecurityRegressionTester: {import_error}')
        
        self.verbosity = options['verbosity']
        self.verbose = options['verbose']
        
        try:
            # Initialize database and tester
            db_path = options.get('db_path')
            database = SecurityRegressionDatabase(db_path)
            tester = SecurityRegressionTester(db_path)
            
            # Handle different operations
            if options['add_fixture']:
                self._add_security_fixture(database, options)
            
            elif options['list_fixtures']:
                self._list_security_fixtures(database, options)
            
            elif options['history']:
                self._show_fixture_history(database, options)
            
            else:
                self._run_regression_tests(tester, options)
            
        except Exception as e:
            raise CommandError(f'Security regression testing failed: {str(e)}')

    def _add_security_fixture(self, database, options):
        """Add a new security fixture"""
        
        if not options.get('fixture_name') or not options.get('fixture_type'):
            raise CommandError('--fixture-name and --fixture-type are required when adding fixtures')
        
        # Get fixture details interactively or from options
        fixture_id = f"{options['fixture_type']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.stdout.write('Creating new security fixture...')
        self.stdout.write(f'Fixture ID: {fixture_id}')
        self.stdout.write(f'Name: {options["fixture_name"]}')
        self.stdout.write(f'Type: {options["fixture_type"]}')
        
        # Create fixture with default test data
        test_data = self._get_default_test_data(options['fixture_type'])
        
        fixture = SecurityFixture(
            fixture_id=fixture_id,
            name=options['fixture_name'],
            description=f'Regression test for {options["fixture_type"]} vulnerability',
            vulnerability_type=options['fixture_type'],
            cve_id=None,
            severity=options['severity'],
            date_fixed=datetime.now().isoformat(),
            test_data=test_data,
            expected_result='secure',
            validation_criteria={'strict_mode': True}
        )
        
        database.add_security_fixture(fixture)
        
        self.stdout.write(
            self.style.SUCCESS(f'✅ Security fixture "{fixture_id}" added successfully')
        )

    def _get_default_test_data(self, fixture_type):
        """Get default test data for different fixture types"""
        
        default_test_data = {
            'sql_injection': {
                'test_url': '/search/',
                'sql_payloads': ["'; DROP TABLE users; --", "' OR '1'='1"]
            },
            'xss': {
                'test_url': '/comments/',
                'xss_payloads': ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
            },
            'csrf': {
                'test_url': '/profile/update/',
                'post_data': {'name': 'test', 'email': 'test@example.com'}
            },
            'authentication': {
                'bypass_attempts': [
                    {'username': 'admin', 'password': 'admin'},
                    {'username': 'admin', 'password': 'password'}
                ]
            },
            'file_upload': {
                'test_url': '/upload/',
                'malicious_files': ['shell.php', 'script.js']
            },
            'access_control': {
                'test_url': '/admin/',
                'unauthorized_access': True
            },
            'session_management': {
                'test_url': '/profile/',
                'session_tests': ['fixation', 'hijacking']
            }
        }
        
        return default_test_data.get(fixture_type, {'test_url': '/', 'custom_test': True})

    def _list_security_fixtures(self, database, options):
        """List all security fixtures"""
        
        vulnerability_types = options['vulnerability_types']
        if 'all' in vulnerability_types:
            vulnerability_types = None
        else:
            vulnerability_types = vulnerability_types[0] if len(vulnerability_types) == 1 else None
        
        fixtures = database.get_security_fixtures(vulnerability_types)
        
        if not fixtures:
            self.stdout.write(self.style.WARNING('No security fixtures found'))
            return
        
        self.stdout.write(f'\n📋 Security Fixtures ({len(fixtures)} total)')
        self.stdout.write('=' * 70)
        
        # Group by vulnerability type
        fixtures_by_type = {}
        for fixture in fixtures:
            if fixture.vulnerability_type not in fixtures_by_type:
                fixtures_by_type[fixture.vulnerability_type] = []
            fixtures_by_type[fixture.vulnerability_type].append(fixture)
        
        for vuln_type, type_fixtures in fixtures_by_type.items():
            self.stdout.write(f'\n📂 {vuln_type.replace("_", " ").title()} ({len(type_fixtures)} fixtures):')
            
            for fixture in type_fixtures:
                severity_style = self._get_severity_style(fixture.severity)
                self.stdout.write(
                    f'  • {fixture.fixture_id}: {fixture.name} '
                    f'({severity_style(fixture.severity.title())})'
                )
                
                if self.verbose:
                    self.stdout.write(f'    Description: {fixture.description}')
                    self.stdout.write(f'    Fixed: {fixture.date_fixed}')
                    if fixture.cve_id:
                        self.stdout.write(f'    CVE: {fixture.cve_id}')

    def _show_fixture_history(self, database, options):
        """Show regression test history for a fixture"""
        
        fixture_id = options['history']
        days = options['days']
        
        history = database.get_regression_history(fixture_id, days)
        
        if not history:
            self.stdout.write(
                self.style.WARNING(f'No test history found for fixture "{fixture_id}" in the last {days} days')
            )
            return
        
        self.stdout.write(f'\n📊 Regression Test History for "{fixture_id}"')
        self.stdout.write(f'Last {days} days ({len(history)} test runs)')
        self.stdout.write('=' * 70)
        
        for entry in history:
            status_style = self._get_status_style(entry['status'])
            regression_indicator = '🚨' if entry['regression_detected'] else '✅'
            
            self.stdout.write(
                f'{regression_indicator} {entry["executed_at"]}: {status_style(entry["status"].upper())}'
            )
            
            if self.verbose:
                self.stdout.write(f'   Test: {entry["test_name"]}')
                self.stdout.write(f'   Time: {entry["execution_time_ms"]:.2f}ms')
                if entry['recommendation']:
                    self.stdout.write(f'   Recommendation: {entry["recommendation"]}')
                
                if entry.get('evidence'):
                    self.stdout.write(f'   Evidence: {json.dumps(entry["evidence"], indent=2)}')

    def _run_regression_tests(self, tester, options):
        """Run security regression tests"""
        
        vulnerability_types = options['vulnerability_types']
        if 'all' in vulnerability_types:
            vulnerability_types = None
        
        if self.verbose:
            self.stdout.write(self.style.HTTP_INFO('Starting security regression tests...'))
            if vulnerability_types:
                self.stdout.write(f'Testing vulnerability types: {", ".join(vulnerability_types)}')
            else:
                self.stdout.write('Testing all vulnerability types')
        
        # Run regression tests
        report = tester.run_regression_tests(vulnerability_types)
        
        # Display results
        self._display_regression_results(report, options)
        
        # Save report if requested
        if options.get('output'):
            self._save_regression_report(report, options['output'])
        
        # Exit with error if regressions detected and requested
        if options['fail_on_regression'] and report['regression_summary']['regressions_detected'] > 0:
            raise CommandError('Security regression tests failed: regressions detected')

    def _display_regression_results(self, report, options):
        """Display regression test results"""
        
        summary = report['regression_summary']
        
        self.stdout.write('\n' + '=' * 70)
        self.stdout.write(self.style.HTTP_INFO('🔄 SECURITY REGRESSION TEST RESULTS'))
        self.stdout.write('=' * 70)
        
        # Overall results
        self.stdout.write(f'Total Tests: {summary["total_tests"]}')
        self.stdout.write(f'✅ Passed: {summary["tests_passed"]}')
        self.stdout.write(f'❌ Failed: {summary["tests_failed"]}')
        self.stdout.write(f'🚨 Regressions: {summary["regressions_detected"]}')
        self.stdout.write(f'⚠️  Errors: {summary["test_errors"]}')
        self.stdout.write(f'📊 Regression Rate: {summary["regression_rate"]:.2f}%')
        
        # Results by vulnerability type
        if report.get('results_by_vulnerability_type'):
            self.stdout.write('\n📂 Results by Vulnerability Type:')
            for vuln_type, count in report['results_by_vulnerability_type'].items():
                self.stdout.write(f'  • {vuln_type.replace("_", " ").title()}: {count} tests')
        
        # Regression details
        if report.get('regression_details') and options.get('verbose'):
            self.stdout.write('\n🚨 Regression Details:')
            for regression in report['regression_details']:
                self.stdout.write(f'  • {regression["test_name"]}:')
                self.stdout.write(f'    Status: {regression["status"]}')
                self.stdout.write(f'    Recommendation: {regression["recommendation"]}')
                
                if regression.get('comparison_data'):
                    comp_data = regression['comparison_data']
                    self.stdout.write(f'    Expected: {comp_data.get("expected_result", "unknown")}')
                    self.stdout.write(f'    Actual: {comp_data.get("actual_result", "unknown")}')
        
        # Recommendations
        if report.get('recommendations'):
            self.stdout.write('\n📋 Recommendations:')
            for rec in report['recommendations']:
                priority_style = self._get_priority_style(rec.get('priority', 'medium'))
                self.stdout.write(f'  • {priority_style(rec.get("title", "No title"))}')
                if self.verbose and rec.get('description'):
                    self.stdout.write(f'    {rec["description"]}')

    def _save_regression_report(self, report, output_path):
        """Save regression report to file"""
        
        try:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.stdout.write(
                self.style.SUCCESS(f'📄 Regression test report saved to: {output_path}')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f'Could not save report: {str(e)}')
            )

    def _get_severity_style(self, severity):
        """Get Django style for severity level"""
        styles = {
            'critical': self.style.ERROR,
            'high': self.style.WARNING,
            'medium': self.style.HTTP_INFO,
            'low': self.style.SUCCESS
        }
        return styles.get(severity, self.style.NOTICE)

    def _get_status_style(self, status):
        """Get Django style for test status"""
        styles = {
            'passed': self.style.SUCCESS,
            'failed': self.style.WARNING,
            'regression': self.style.ERROR,
            'error': self.style.ERROR,
            'warning': self.style.WARNING
        }
        return styles.get(status, self.style.NOTICE)

    def _get_priority_style(self, priority):
        """Get Django style for priority level"""
        styles = {
            'critical': self.style.ERROR,
            'high': self.style.WARNING,
            'medium': self.style.HTTP_INFO,
            'low': self.style.SUCCESS
        }
        return styles.get(priority, self.style.NOTICE)
