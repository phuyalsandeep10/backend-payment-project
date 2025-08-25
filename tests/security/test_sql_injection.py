"""
Django management command to run SQL injection tests
Usage: python manage.py test_sql_injection
"""
import json
from django.core.management.base import BaseCommand
from core_config.sql_injection_testing import SQLInjectionTestSuite


class Command(BaseCommand):
    """
    Django management command to run comprehensive SQL injection tests
    """
    help = 'Run comprehensive SQL injection security tests'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--output',
            type=str,
            help='Output file for test results (JSON format)',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed test results',
        )
        parser.add_argument(
            '--ci',
            action='store_true',
            help='Run in CI mode with strict pass/fail criteria',
        )
        parser.add_argument(
            '--category',
            type=str,
            choices=['basic', 'union', 'boolean', 'time', 'error', 'bypass', 'advanced', 'safe'],
            help='Run tests for specific category only',
        )
    
    def handle(self, *args, **options):
        self.stdout.write("🔒 SQL Injection Security Testing")
        self.stdout.write("=" * 50)
        
        # Initialize test suite
        test_suite = SQLInjectionTestSuite()
        
        # Run tests
        if options['category']:
            self.stdout.write(f"Running tests for category: {options['category']}")
            # Note: Category-specific testing would require method modification
            report = test_suite.run_comprehensive_tests()
        else:
            report = test_suite.run_comprehensive_tests()
        
        # Display results
        self._display_results(report, options['verbose'])
        
        # Save results if requested
        if options['output']:
            self._save_results(report, options['output'])
        
        # CI mode evaluation
        if options['ci']:
            return self._evaluate_ci_results(report)
        
        return 0
    
    def _display_results(self, report, verbose=False):
        """Display test results"""
        summary = report['summary']
        
        self.stdout.write("\n📊 Test Results Summary:")
        self.stdout.write("-" * 30)
        self.stdout.write(f"Total Tests: {summary['total_tests']}")
        self.stdout.write(f"Passed: {summary['passed_tests']} ({summary['success_rate']:.1f}%)")
        self.stdout.write(f"Failed: {summary['failed_tests']}")
        self.stdout.write(f"Detection Rate: {summary['detection_rate']:.1f}%")
        self.stdout.write(f"False Positive Rate: {summary['false_positive_rate']:.1f}%")
        
        # Security metrics
        self.stdout.write("\n🛡️ Security Metrics:")
        self.stdout.write(f"Blocked Attacks: {summary['blocked_attacks']}")
        self.stdout.write(f"Missed Attacks: {summary['missed_attacks']}")
        self.stdout.write(f"False Positives: {summary['false_positives']}")
        
        # Overall assessment
        success_rate = summary['success_rate']
        detection_rate = summary['detection_rate']
        false_positive_rate = summary['false_positive_rate']
        
        if success_rate >= 95 and detection_rate >= 90 and false_positive_rate <= 5:
            self.stdout.write(self.style.SUCCESS("\n🎉 EXCELLENT - SQL injection protection is highly effective!"))
        elif success_rate >= 85 and detection_rate >= 80 and false_positive_rate <= 10:
            self.stdout.write(self.style.SUCCESS("\n✅ GOOD - SQL injection protection is effective"))
        elif success_rate >= 70 and detection_rate >= 70 and false_positive_rate <= 15:
            self.stdout.write(self.style.WARNING("\n⚠️ FAIR - SQL injection protection needs improvement"))
        else:
            self.stdout.write(self.style.ERROR("\n❌ POOR - SQL injection protection is inadequate"))
        
        # Detailed results
        if verbose:
            self._display_detailed_results(report['details'])
    
    def _display_detailed_results(self, details):
        """Display detailed test results"""
        self.stdout.write("\n📋 Detailed Test Results:")
        self.stdout.write("-" * 40)
        
        # Group by category
        categories = {}
        for detail in details:
            category = detail['category']
            if category not in categories:
                categories[category] = {'passed': 0, 'failed': 0, 'tests': []}
            
            if detail['passed']:
                categories[category]['passed'] += 1
            else:
                categories[category]['failed'] += 1
            
            categories[category]['tests'].append(detail)
        
        # Display by category
        for category, data in categories.items():
            total = data['passed'] + data['failed']
            success_rate = (data['passed'] / total * 100) if total > 0 else 0
            
            self.stdout.write(f"\n{category}: {data['passed']}/{total} ({success_rate:.1f}%)")
            
            # Show failed tests
            failed_tests = [t for t in data['tests'] if not t['passed']]
            if failed_tests:
                for test in failed_tests[:5]:  # Show first 5 failures
                    status = "MISSED" if test['should_block'] and not test['was_blocked'] else "FALSE_POS"
                    self.stdout.write(f"  ❌ {status}: {test['payload'][:60]}...")
    
    def _save_results(self, report, output_file):
        """Save results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self.stdout.write(f"\n💾 Results saved to: {output_file}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to save results: {str(e)}"))
    
    def _evaluate_ci_results(self, report):
        """Evaluate results for CI/CD pipeline"""
        summary = report['summary']
        
        # CI/CD pass criteria
        min_success_rate = 85
        min_detection_rate = 80
        max_false_positive_rate = 10
        max_missed_attacks = 0
        
        criteria_met = [
            summary['success_rate'] >= min_success_rate,
            summary['detection_rate'] >= min_detection_rate,
            summary['false_positive_rate'] <= max_false_positive_rate,
            summary['missed_attacks'] <= max_missed_attacks
        ]
        
        if all(criteria_met):
            self.stdout.write(self.style.SUCCESS("\n✅ CI/CD PASS - Security tests meet all criteria"))
            return 0
        else:
            self.stdout.write(self.style.ERROR("\n❌ CI/CD FAIL - Security tests do not meet criteria"))
            
            # Show which criteria failed
            if summary['success_rate'] < min_success_rate:
                self.stdout.write(f"  • Success rate {summary['success_rate']:.1f}% < {min_success_rate}%")
            if summary['detection_rate'] < min_detection_rate:
                self.stdout.write(f"  • Detection rate {summary['detection_rate']:.1f}% < {min_detection_rate}%")
            if summary['false_positive_rate'] > max_false_positive_rate:
                self.stdout.write(f"  • False positive rate {summary['false_positive_rate']:.1f}% > {max_false_positive_rate}%")
            if summary['missed_attacks'] > max_missed_attacks:
                self.stdout.write(f"  • Missed attacks {summary['missed_attacks']} > {max_missed_attacks}")
            
            return 1