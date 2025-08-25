"""
Django management command for running comprehensive security tests
Task 6.1.1: Security test framework command integration
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
    from security.security_test_framework import SecurityTestFramework
except ImportError as e:
    SecurityTestFramework = None
    import_error = str(e)


class Command(BaseCommand):
    help = 'Run comprehensive security tests using the security test framework'

    def add_arguments(self, parser):
        parser.add_argument(
            '--category',
            type=str,
            choices=[
                'authentication', 'injection', 'xss', 'csrf', 'file_upload',
                'session', 'encryption', 'configuration', 'input_validation',
                'access_control', 'all'
            ],
            default='all',
            help='Security test category to run (default: all)'
        )
        
        parser.add_argument(
            '--severity',
            type=str,
            choices=['critical', 'high', 'medium', 'low', 'info', 'all'],
            default='all',
            help='Minimum severity level to report (default: all)'
        )
        
        parser.add_argument(
            '--output',
            type=str,
            help='Output file path for security report (JSON format)'
        )
        
        parser.add_argument(
            '--format',
            type=str,
            choices=['json', 'html', 'text'],
            default='text',
            help='Output format for the report'
        )
        
        parser.add_argument(
            '--fail-on',
            type=str,
            choices=['critical', 'high', 'medium', 'low'],
            default='high',
            help='Fail command if vulnerabilities of this severity or higher are found'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
        
        parser.add_argument(
            '--quick',
            action='store_true',
            help='Run quick security scan (reduced test coverage)'
        )

    def handle(self, *args, **options):
        if SecurityTestFramework is None:
            raise CommandError(f'Could not import SecurityTestFramework: {import_error}')
        
        self.verbosity = options['verbosity']
        self.verbose = options['verbose']
        
        try:
            if self.verbose:
                self.stdout.write(self.style.HTTP_INFO('Initializing Security Test Framework...'))
            
            # Initialize framework
            framework = SecurityTestFramework()
            
            # Configure framework based on options
            if options['quick']:
                framework = self._configure_quick_scan(framework)
            
            # Run security tests
            if self.verbose:
                self.stdout.write(self.style.HTTP_INFO(f'Running security tests (category: {options["category"]})...'))
            
            if options['category'] == 'all':
                report = framework.run_comprehensive_security_tests()
            else:
                report = self._run_category_specific_tests(framework, options['category'])
            
            # Process and display results
            self._process_results(report, options)
            
            # Determine exit status
            should_fail = self._should_fail(report, options['fail_on'])
            if should_fail:
                raise CommandError('Security tests failed due to high-severity vulnerabilities')
            
            self.stdout.write(
                self.style.SUCCESS('Security tests completed successfully')
            )
            
        except Exception as e:
            raise CommandError(f'Security test execution failed: {str(e)}')

    def _configure_quick_scan(self, framework):
        """Configure framework for quick security scan"""
        # Reduce test coverage for faster execution
        framework.quick_scan = True
        return framework

    def _run_category_specific_tests(self, framework, category):
        """Run tests for specific category"""
        framework.setup_test_environment()
        
        category_methods = {
            'authentication': framework._run_authentication_tests,
            'injection': framework._run_injection_tests,
            'xss': framework._run_xss_tests,
            'csrf': framework._run_csrf_tests,
            'file_upload': framework._run_file_upload_tests,
            'session': framework._run_session_tests,
            'encryption': framework._run_encryption_tests,
            'configuration': framework._run_configuration_tests,
            'input_validation': framework._run_input_validation_tests,
            'access_control': framework._run_access_control_tests
        }
        
        if category in category_methods:
            self.stdout.write(f'Running {category} security tests...')
            category_methods[category]()
        
        return framework._generate_security_report()

    def _process_results(self, report, options):
        """Process and display test results"""
        
        # Filter by severity if specified
        if options['severity'] != 'all':
            report = self._filter_by_severity(report, options['severity'])
        
        # Display results based on format
        if options['format'] == 'json':
            self._display_json_results(report)
        elif options['format'] == 'html':
            self._display_html_results(report)
        else:
            self._display_text_results(report, options)
        
        # Save to file if specified
        if options['output']:
            self._save_results(report, options['output'], options['format'])

    def _display_text_results(self, report, options):
        """Display results in text format"""
        summary = report['executive_summary']
        
        self.stdout.write('\n' + '=' * 70)
        self.stdout.write(self.style.HTTP_INFO('🛡️  SECURITY TEST RESULTS'))
        self.stdout.write('=' * 70)
        
        # Overall results
        self.stdout.write(f'Security Score: {summary["overall_security_score"]}/100')
        self.stdout.write(f'Risk Level: {self._colorize_risk_level(summary["risk_level"])}')
        self.stdout.write(f'Tests Run: {summary["total_tests"]}')
        
        # Test results breakdown
        self.stdout.write(f'✅ Passed: {summary["tests_passed"]}')
        self.stdout.write(f'❌ Failed: {summary["tests_failed"]}')
        self.stdout.write(f'⚠️  Warnings: {summary["warnings"]}')
        self.stdout.write(f'🚨 Vulnerabilities: {summary["vulnerabilities_found"]}')
        
        # Severity breakdown
        if report.get('severity_breakdown'):
            self.stdout.write('\n📊 Severity Breakdown:')
            for severity, count in report['severity_breakdown'].items():
                if count > 0:
                    emoji = self._get_severity_emoji(severity)
                    style = self._get_severity_style(severity)
                    self.stdout.write(f'  {emoji} {severity.title()}: {style(str(count))}')
        
        # Failed tests details
        if summary['tests_failed'] > 0 and options['verbose']:
            self._display_failed_tests(report)
        
        # Recommendations
        if report.get('recommendations'):
            self.stdout.write('\n📋 Security Recommendations:')
            for i, rec in enumerate(report['recommendations'][:5], 1):
                priority_style = self.style.ERROR if rec.get('priority') == 'high' else self.style.WARNING
                self.stdout.write(f'  {i}. {priority_style(rec["recommendation"])}')
        
        # Vulnerabilities summary
        if report.get('vulnerabilities'):
            self.stdout.write(f'\n🚨 Critical Vulnerabilities Found: {len(report["vulnerabilities"])}')
            for vuln in report['vulnerabilities'][:3]:  # Show top 3
                self.stdout.write(f'  • {vuln["title"]}: {vuln["description"][:80]}...')

    def _display_failed_tests(self, report):
        """Display details of failed tests"""
        self.stdout.write('\n❌ Failed Tests Details:')
        
        for category, results in report['test_results_by_category'].items():
            failed_results = [r for r in results if r['status'] == 'failed']
            if failed_results:
                self.stdout.write(f'\n  📂 {category.title()}:')
                for result in failed_results[:3]:  # Show top 3 per category
                    severity_style = self._get_severity_style(result['severity'])
                    self.stdout.write(
                        f'    • {severity_style(result["test_name"])}: {result["description"][:60]}...'
                    )

    def _colorize_risk_level(self, risk_level):
        """Apply color styling to risk level"""
        styles = {
            'CRITICAL': self.style.ERROR,
            'HIGH': self.style.WARNING,
            'MEDIUM': self.style.HTTP_INFO,
            'LOW': self.style.SUCCESS
        }
        return styles.get(risk_level, self.style.NOTICE)(risk_level)

    def _get_severity_emoji(self, severity):
        """Get emoji for severity level"""
        emojis = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'info': '🔵'
        }
        return emojis.get(severity, '⚪')

    def _get_severity_style(self, severity):
        """Get Django style for severity level"""
        styles = {
            'critical': self.style.ERROR,
            'high': self.style.WARNING,
            'medium': self.style.HTTP_INFO,
            'low': self.style.SUCCESS,
            'info': self.style.NOTICE
        }
        return styles.get(severity, self.style.NOTICE)

    def _display_json_results(self, report):
        """Display results in JSON format"""
        self.stdout.write(json.dumps(report, indent=2, default=str))

    def _display_html_results(self, report):
        """Display results in HTML format"""
        html_template = self._generate_html_report(report)
        self.stdout.write(html_template)

    def _generate_html_report(self, report):
        """Generate HTML report template"""
        summary = report['executive_summary']
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
                .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .metric {{ text-align: center; padding: 10px; }}
                .critical {{ color: #dc3545; }}
                .high {{ color: #fd7e14; }}
                .medium {{ color: #ffc107; }}
                .low {{ color: #28a745; }}
                .passed {{ color: #28a745; }}
                .failed {{ color: #dc3545; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Security Test Report</h1>
                <p>Generated: {report['report_metadata']['generated_at']}</p>
                <p>Security Score: <strong>{summary['overall_security_score']}/100</strong></p>
                <p>Risk Level: <strong>{summary['risk_level']}</strong></p>
            </div>
            
            <div class="summary">
                <div class="metric">
                    <h3>Tests Run</h3>
                    <p><strong>{summary['total_tests']}</strong></p>
                </div>
                <div class="metric">
                    <h3 class="passed">Passed</h3>
                    <p><strong>{summary['tests_passed']}</strong></p>
                </div>
                <div class="metric">
                    <h3 class="failed">Failed</h3>
                    <p><strong>{summary['tests_failed']}</strong></p>
                </div>
                <div class="metric">
                    <h3>Vulnerabilities</h3>
                    <p><strong>{summary['vulnerabilities_found']}</strong></p>
                </div>
            </div>
            
            <h2>Test Results by Category</h2>
            <!-- Category results would be expanded here -->
            
            <h2>Recommendations</h2>
            <ul>
        """
        
        for rec in report.get('recommendations', [])[:5]:
            html += f"<li>{rec.get('recommendation', 'No recommendation')}</li>"
        
        html += """
            </ul>
        </body>
        </html>
        """
        
        return html

    def _filter_by_severity(self, report, min_severity):
        """Filter report results by minimum severity level"""
        severity_levels = ['info', 'low', 'medium', 'high', 'critical']
        min_level_index = severity_levels.index(min_severity)
        
        # Filter detailed results
        filtered_results = []
        for result in report['detailed_results']:
            if severity_levels.index(result['severity']) >= min_level_index:
                filtered_results.append(result)
        
        report['detailed_results'] = filtered_results
        
        # Update category results
        filtered_categories = {}
        for category, results in report['test_results_by_category'].items():
            filtered_category_results = []
            for result in results:
                if severity_levels.index(result['severity']) >= min_level_index:
                    filtered_category_results.append(result)
            if filtered_category_results:
                filtered_categories[category] = filtered_category_results
        
        report['test_results_by_category'] = filtered_categories
        return report

    def _save_results(self, report, output_path, format_type):
        """Save results to file"""
        try:
            with open(output_path, 'w') as f:
                if format_type == 'json':
                    json.dump(report, f, indent=2, default=str)
                elif format_type == 'html':
                    f.write(self._generate_html_report(report))
                else:
                    # Save text format
                    f.write(f"Security Test Report - {report['report_metadata']['generated_at']}\n")
                    f.write("=" * 70 + "\n")
                    f.write(f"Security Score: {report['executive_summary']['overall_security_score']}/100\n")
                    f.write(f"Risk Level: {report['executive_summary']['risk_level']}\n")
                    f.write(f"Tests: {report['executive_summary']['total_tests']} run, ")
                    f.write(f"{report['executive_summary']['tests_passed']} passed, ")
                    f.write(f"{report['executive_summary']['tests_failed']} failed\n")
                    f.write(f"Vulnerabilities Found: {report['executive_summary']['vulnerabilities_found']}\n")
            
            self.stdout.write(
                self.style.SUCCESS(f'Report saved to: {output_path}')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f'Could not save report: {str(e)}')
            )

    def _should_fail(self, report, fail_on_severity):
        """Determine if command should fail based on vulnerability severity"""
        severity_levels = ['low', 'medium', 'high', 'critical']
        fail_level_index = severity_levels.index(fail_on_severity)
        
        for result in report.get('detailed_results', []):
            if result['status'] == 'failed':
                result_severity_index = severity_levels.index(result['severity'])
                if result_severity_index >= fail_level_index:
                    return True
        
        return False
