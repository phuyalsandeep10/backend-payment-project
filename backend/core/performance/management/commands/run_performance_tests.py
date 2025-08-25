"""
Performance Test Management Command - Task 6.2.1

Django management command for running performance tests, benchmarks, and regression tests
from the command line and CI/CD pipelines.
"""

import sys
import os
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.conf import settings
import json

# Add the tests directory to Python path
tests_path = os.path.join(os.path.dirname(settings.BASE_DIR), 'tests')
if tests_path not in sys.path:
    sys.path.insert(0, tests_path)

try:
    from performance.performance_test_framework import (
        PerformanceTestFramework, 
        LoadTestConfig, 
        create_api_load_test_scenarios
    )
except ImportError as e:
    # Fallback for development
    print(f"Warning: Could not import performance framework: {e}")
    PerformanceTestFramework = None

User = get_user_model()


class Command(BaseCommand):
    help = 'Run performance tests, establish baselines, and perform regression testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=['load-test', 'baseline', 'regression', 'scenarios', 'health-check'],
            required=True,
            help='Action to perform'
        )
        
        parser.add_argument(
            '--url',
            type=str,
            help='Target URL for testing (e.g., /api/health/)'
        )
        
        parser.add_argument(
            '--base-url',
            type=str,
            default='http://localhost:8000',
            help='Base URL for the application (default: http://localhost:8000)'
        )
        
        parser.add_argument(
            '--users',
            type=int,
            default=10,
            help='Number of concurrent users (default: 10)'
        )
        
        parser.add_argument(
            '--requests',
            type=int,
            default=100,
            help='Number of requests per user (default: 100)'
        )
        
        parser.add_argument(
            '--method',
            type=str,
            default='GET',
            choices=['GET', 'POST', 'PUT', 'DELETE'],
            help='HTTP method (default: GET)'
        )
        
        parser.add_argument(
            '--payload',
            type=str,
            help='JSON payload for POST/PUT requests'
        )
        
        parser.add_argument(
            '--auth-token',
            type=str,
            help='Authorization token for authenticated requests'
        )
        
        parser.add_argument(
            '--test-name',
            type=str,
            help='Name for baseline/regression test'
        )
        
        parser.add_argument(
            '--version',
            type=str,
            default='1.0.0',
            help='Version for baseline establishment (default: 1.0.0)'
        )
        
        parser.add_argument(
            '--tolerance',
            type=float,
            default=10.0,
            help='Tolerance percentage for regression testing (default: 10.0)'
        )
        
        parser.add_argument(
            '--ramp-up',
            type=float,
            default=30.0,
            help='Ramp-up time in seconds (default: 30.0)'
        )
        
        parser.add_argument(
            '--think-time',
            type=float,
            default=0.1,
            help='Think time between requests in seconds (default: 0.1)'
        )
        
        parser.add_argument(
            '--duration',
            type=float,
            help='Test duration in seconds (overrides --requests)'
        )
        
        parser.add_argument(
            '--output-format',
            type=str,
            choices=['text', 'json', 'csv'],
            default='text',
            help='Output format for results (default: text)'
        )
        
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress detailed output'
        )

    def handle(self, *args, **options):
        if PerformanceTestFramework is None:
            raise CommandError(
                'Performance test framework not available. '
                'Please ensure the performance test framework is properly installed.'
            )
        
        action = options['action']
        
        # Initialize framework
        framework = PerformanceTestFramework(base_url=options['base_url'])
        
        if not options['quiet']:
            self.stdout.write(
                self.style.SUCCESS(f"🚀 Performance Test Framework - Action: {action}")
            )
        
        try:
            if action == 'load-test':
                self.handle_load_test(framework, options)
            elif action == 'baseline':
                self.handle_baseline(framework, options)
            elif action == 'regression':
                self.handle_regression(framework, options)
            elif action == 'scenarios':
                self.handle_scenarios(framework, options)
            elif action == 'health-check':
                self.handle_health_check(framework, options)
        
        except Exception as e:
            raise CommandError(f'Performance test failed: {str(e)}')

    def handle_load_test(self, framework, options):
        """Handle load test execution"""
        if not options['url']:
            raise CommandError('--url is required for load-test action')
        
        # Parse payload if provided
        payload = None
        if options['payload']:
            try:
                payload = json.loads(options['payload'])
            except json.JSONDecodeError:
                raise CommandError('Invalid JSON payload')
        
        # Create test configuration
        config = LoadTestConfig(
            target_url=options['url'],
            concurrent_users=options['users'],
            requests_per_user=options['requests'],
            method=options['method'],
            payload=payload,
            auth_token=options['auth_token'],
            ramp_up_time=options['ramp_up'],
            think_time=options['think_time'],
            test_duration=options['duration']
        )
        
        if not options['quiet']:
            self.stdout.write(f"Running load test for {options['url']}")
        
        # Run load test
        result = framework.run_load_test(config)
        
        # Output results
        self.output_results(result, options['output_format'])
        
        # Suggest baseline establishment if none exists
        test_name = options['test_name'] or f"load_test_{options['url'].replace('/', '_').replace('-', '_')}"
        if test_name not in framework.baselines:
            self.stdout.write(
                self.style.WARNING(
                    f"💡 No baseline exists for {test_name}. "
                    f"Run with --action=baseline to establish one."
                )
            )

    def handle_baseline(self, framework, options):
        """Handle baseline establishment"""
        if not options['url']:
            raise CommandError('--url is required for baseline action')
        
        test_name = options['test_name'] or f"baseline_{options['url'].replace('/', '_').replace('-', '_')}"
        
        # First run a load test
        config = LoadTestConfig(
            target_url=options['url'],
            concurrent_users=options['users'],
            requests_per_user=options['requests'],
            method=options['method'],
            ramp_up_time=options['ramp_up'],
            think_time=options['think_time']
        )
        
        if not options['quiet']:
            self.stdout.write(f"Establishing baseline for {test_name}")
        
        result = framework.run_load_test(config)
        baseline = framework.establish_baseline(test_name, result, options['version'])
        
        self.stdout.write(
            self.style.SUCCESS(f"✅ Baseline established for {test_name}")
        )

    def handle_regression(self, framework, options):
        """Handle regression testing"""
        if not options['url']:
            raise CommandError('--url is required for regression action')
        
        test_name = options['test_name'] or f"baseline_{options['url'].replace('/', '_').replace('-', '_')}"
        
        # Run current performance test
        config = LoadTestConfig(
            target_url=options['url'],
            concurrent_users=options['users'],
            requests_per_user=options['requests'],
            method=options['method'],
            ramp_up_time=options['ramp_up'],
            think_time=options['think_time']
        )
        
        if not options['quiet']:
            self.stdout.write(f"Running regression test against {test_name}")
        
        current_result = framework.run_load_test(config)
        regression_report = framework.run_regression_test(
            test_name, current_result, options['tolerance']
        )
        
        # Exit with error if regressions detected
        if regression_report['status'] == 'failed':
            raise CommandError('Performance regressions detected!')
        elif regression_report['status'] == 'no_baseline':
            raise CommandError('No baseline found for regression testing!')

    def handle_scenarios(self, framework, options):
        """Handle predefined scenario testing"""
        scenarios = create_api_load_test_scenarios()
        
        if not options['quiet']:
            self.stdout.write(f"Running {len(scenarios)} predefined scenarios")
        
        results = []
        
        for i, scenario in enumerate(scenarios, 1):
            if not options['quiet']:
                self.stdout.write(f"\n--- Scenario {i}/{len(scenarios)}: {scenario.target_url} ---")
            
            try:
                result = framework.run_load_test(scenario)
                results.append({
                    'scenario': i,
                    'url': scenario.target_url,
                    'success': True,
                    'avg_response_time': result.avg_response_time,
                    'throughput_rps': result.throughput_rps,
                    'success_rate': (result.successful_requests / result.total_requests) * 100
                })
            except Exception as e:
                if not options['quiet']:
                    self.stdout.write(
                        self.style.ERROR(f"Scenario {i} failed: {str(e)}")
                    )
                results.append({
                    'scenario': i,
                    'url': scenario.target_url,
                    'success': False,
                    'error': str(e)
                })
        
        # Summary
        successful_scenarios = sum(1 for r in results if r['success'])
        self.stdout.write(
            self.style.SUCCESS(
                f"\n📊 Scenarios Summary: {successful_scenarios}/{len(scenarios)} successful"
            )
        )
        
        if options['output_format'] == 'json':
            self.stdout.write(json.dumps(results, indent=2))

    def handle_health_check(self, framework, options):
        """Handle system health check with performance validation"""
        health_endpoints = [
            '/api/health/',
            '/api/monitoring/health/',
            '/api/auth/health/'
        ]
        
        if not options['quiet']:
            self.stdout.write("🏥 Running system health check with performance validation")
        
        all_healthy = True
        
        for endpoint in health_endpoints:
            try:
                config = LoadTestConfig(
                    target_url=endpoint,
                    concurrent_users=5,
                    requests_per_user=10,
                    think_time=0.1
                )
                
                result = framework.run_load_test(config)
                
                # Health check criteria
                avg_response_ok = result.avg_response_time < 0.5  # 500ms
                success_rate_ok = (result.successful_requests / result.total_requests) >= 0.95  # 95%
                
                status = "✅ HEALTHY" if avg_response_ok and success_rate_ok else "❌ UNHEALTHY"
                
                if not options['quiet'] or not (avg_response_ok and success_rate_ok):
                    self.stdout.write(
                        f"{endpoint}: {status} "
                        f"(avg: {result.avg_response_time:.3f}s, "
                        f"success: {(result.successful_requests / result.total_requests) * 100:.1f}%)"
                    )
                
                if not (avg_response_ok and success_rate_ok):
                    all_healthy = False
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"{endpoint}: ❌ ERROR - {str(e)}")
                )
                all_healthy = False
        
        if all_healthy:
            self.stdout.write(self.style.SUCCESS("🎉 All health checks passed!"))
        else:
            raise CommandError('One or more health checks failed!')

    def output_results(self, result, format_type):
        """Output results in specified format"""
        if format_type == 'json':
            output = {
                'test_name': result.test_name,
                'duration_seconds': (result.end_time - result.start_time).total_seconds(),
                'total_requests': result.total_requests,
                'successful_requests': result.successful_requests,
                'failed_requests': result.failed_requests,
                'success_rate_percent': (result.successful_requests / result.total_requests) * 100,
                'avg_response_time': result.avg_response_time,
                'median_response_time': result.median_response_time,
                'percentile_95': result.percentile_95,
                'percentile_99': result.percentile_99,
                'throughput_rps': result.throughput_rps,
                'peak_memory_mb': result.peak_memory_mb,
                'avg_cpu_percent': result.avg_cpu_percent
            }
            self.stdout.write(json.dumps(output, indent=2))
        
        elif format_type == 'csv':
            headers = [
                'test_name', 'duration_seconds', 'total_requests', 'successful_requests',
                'success_rate_percent', 'avg_response_time', 'median_response_time',
                'percentile_95', 'percentile_99', 'throughput_rps', 'peak_memory_mb', 'avg_cpu_percent'
            ]
            
            values = [
                result.test_name,
                (result.end_time - result.start_time).total_seconds(),
                result.total_requests,
                result.successful_requests,
                (result.successful_requests / result.total_requests) * 100,
                result.avg_response_time,
                result.median_response_time,
                result.percentile_95,
                result.percentile_99,
                result.throughput_rps,
                result.peak_memory_mb,
                result.avg_cpu_percent
            ]
            
            self.stdout.write(','.join(headers))
            self.stdout.write(','.join(map(str, values)))
