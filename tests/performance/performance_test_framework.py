"""
Comprehensive Performance Test Framework - Task 6.2.1

Load testing capabilities, performance regression testing, and benchmarking suite
for the Backend_PRS application.
"""

import os
import sys
import django
import json
import time
import threading
import concurrent.futures
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, asdict, field
from statistics import mean, median, stdev
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import psutil

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.db import connection
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

User = get_user_model()


@dataclass
class LoadTestConfig:
    """Configuration for load testing"""
    target_url: str
    concurrent_users: int = 10
    requests_per_user: int = 100
    ramp_up_time: float = 30.0  # seconds
    test_duration: Optional[float] = None  # seconds, overrides requests_per_user
    think_time: float = 0.1  # seconds between requests
    timeout: float = 30.0  # request timeout
    
    # Request configuration
    headers: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    method: str = 'GET'
    
    # Test scenarios
    scenarios: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PerformanceMetric:
    """Individual performance measurement"""
    test_name: str
    timestamp: datetime
    response_time: float  # seconds
    status_code: int
    success: bool
    error_message: Optional[str] = None
    user_id: Optional[int] = None
    endpoint: Optional[str] = None
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None


@dataclass
class LoadTestResult:
    """Results from a load test"""
    test_name: str
    config: LoadTestConfig
    start_time: datetime
    end_time: datetime
    total_requests: int
    successful_requests: int
    failed_requests: int
    
    # Performance metrics
    avg_response_time: float
    median_response_time: float
    min_response_time: float
    max_response_time: float
    percentile_95: float
    percentile_99: float
    throughput_rps: float  # requests per second
    
    # System metrics
    peak_memory_mb: float
    avg_cpu_percent: float
    
    # Detailed results
    metrics: List[PerformanceMetric] = field(default_factory=list)
    error_distribution: Dict[str, int] = field(default_factory=dict)
    status_code_distribution: Dict[int, int] = field(default_factory=dict)


@dataclass
class BenchmarkBaseline:
    """Performance baseline for regression testing"""
    test_name: str
    date_established: datetime
    environment: str
    
    # Performance baselines
    avg_response_time: float
    median_response_time: float
    percentile_95: float
    percentile_99: float
    throughput_rps: float
    error_rate_percent: float
    
    # System baselines
    memory_usage_mb: float
    cpu_usage_percent: float
    
    # Metadata
    version: str
    git_commit: Optional[str] = None
    configuration: Dict[str, Any] = field(default_factory=dict)


class PerformanceTestFramework:
    """
    Comprehensive performance testing framework
    Task 6.2.1: Load testing, regression testing, and benchmarking
    """
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = self._create_session()
        self.baselines_file = "Backend_PRS/tests/performance/performance_baselines.json"
        self.results_dir = "Backend_PRS/tests/performance/results"
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.baselines_file), exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Load existing baselines
        self.baselines = self._load_baselines()
        
        print("🚀 Performance Test Framework Initialized")
        print(f"Base URL: {self.base_url}")
        print(f"Results Directory: {self.results_dir}")
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry strategy"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def run_load_test(self, config: LoadTestConfig) -> LoadTestResult:
        """
        Run comprehensive load test
        Task 6.2.1: Load testing capabilities
        """
        print(f"\n🔥 LOAD TEST: {config.target_url}")
        print("=" * 60)
        print(f"Concurrent Users: {config.concurrent_users}")
        print(f"Requests per User: {config.requests_per_user}")
        print(f"Ramp-up Time: {config.ramp_up_time}s")
        print(f"Think Time: {config.think_time}s")
        print()
        
        start_time = datetime.now()
        metrics = []
        system_metrics = []
        
        # Start system monitoring
        stop_monitoring = threading.Event()
        monitor_thread = threading.Thread(
            target=self._monitor_system_resources,
            args=(system_metrics, stop_monitoring)
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        try:
            # Run concurrent load test
            with concurrent.futures.ThreadPoolExecutor(max_workers=config.concurrent_users) as executor:
                # Create futures for all users
                futures = []
                
                for user_id in range(config.concurrent_users):
                    # Stagger user start times for ramp-up
                    delay = (config.ramp_up_time * user_id) / config.concurrent_users
                    
                    future = executor.submit(
                        self._run_user_simulation,
                        config, user_id, delay
                    )
                    futures.append(future)
                
                # Collect results from all users
                for future in concurrent.futures.as_completed(futures):
                    try:
                        user_metrics = future.result()
                        metrics.extend(user_metrics)
                    except Exception as e:
                        print(f"⚠️ User simulation failed: {e}")
        
        finally:
            # Stop system monitoring
            stop_monitoring.set()
            monitor_thread.join(timeout=5)
        
        end_time = datetime.now()
        
        # Calculate results
        result = self._calculate_load_test_results(
            config, start_time, end_time, metrics, system_metrics
        )
        
        # Save results
        self._save_load_test_results(result)
        
        # Print summary
        self._print_load_test_summary(result)
        
        return result
    
    def _run_user_simulation(
        self, 
        config: LoadTestConfig, 
        user_id: int, 
        delay: float
    ) -> List[PerformanceMetric]:
        """Simulate a single user's load testing"""
        # Wait for ramp-up
        if delay > 0:
            time.sleep(delay)
        
        metrics = []
        session = self._create_session()
        
        # Add authentication if provided
        headers = config.headers.copy()
        if config.auth_token:
            headers['Authorization'] = f'Bearer {config.auth_token}'
        
        # Determine number of requests
        if config.test_duration:
            # Run for specified duration
            end_time = time.time() + config.test_duration
            request_count = 0
            while time.time() < end_time:
                metric = self._make_request(config, session, headers, user_id)
                metrics.append(metric)
                request_count += 1
                
                if config.think_time > 0:
                    time.sleep(config.think_time)
        else:
            # Run specified number of requests
            for request_num in range(config.requests_per_user):
                metric = self._make_request(config, session, headers, user_id)
                metrics.append(metric)
                
                if config.think_time > 0 and request_num < config.requests_per_user - 1:
                    time.sleep(config.think_time)
        
        session.close()
        return metrics
    
    def _make_request(
        self,
        config: LoadTestConfig,
        session: requests.Session,
        headers: Dict[str, str],
        user_id: int
    ) -> PerformanceMetric:
        """Make a single HTTP request and measure performance"""
        url = f"{self.base_url}{config.target_url}"
        start_time = time.time()
        
        try:
            # Get system metrics before request
            process = psutil.Process()
            memory_before = process.memory_info().rss / 1024 / 1024  # MB
            cpu_before = process.cpu_percent()
            
            # Make request
            if config.method.upper() == 'GET':
                response = session.get(url, headers=headers, timeout=config.timeout)
            elif config.method.upper() == 'POST':
                response = session.post(url, headers=headers, json=config.payload, timeout=config.timeout)
            elif config.method.upper() == 'PUT':
                response = session.put(url, headers=headers, json=config.payload, timeout=config.timeout)
            elif config.method.upper() == 'DELETE':
                response = session.delete(url, headers=headers, timeout=config.timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {config.method}")
            
            response_time = time.time() - start_time
            success = 200 <= response.status_code < 400
            error_message = None if success else response.text[:200]
            
            # Get system metrics after request
            memory_after = process.memory_info().rss / 1024 / 1024  # MB
            
        except Exception as e:
            response_time = time.time() - start_time
            success = False
            error_message = str(e)
            status_code = 0
            memory_after = memory_before
        else:
            status_code = response.status_code
        
        return PerformanceMetric(
            test_name=f"load_test_{config.target_url}",
            timestamp=datetime.now(),
            response_time=response_time,
            status_code=status_code,
            success=success,
            error_message=error_message,
            user_id=user_id,
            endpoint=config.target_url,
            memory_usage_mb=memory_after,
            cpu_usage_percent=cpu_before
        )
    
    def _monitor_system_resources(self, system_metrics: List[Dict], stop_event: threading.Event):
        """Monitor system resources during load test"""
        while not stop_event.is_set():
            try:
                metrics = {
                    'timestamp': datetime.now(),
                    'cpu_percent': psutil.cpu_percent(interval=1),
                    'memory_percent': psutil.virtual_memory().percent,
                    'memory_mb': psutil.virtual_memory().used / 1024 / 1024,
                    'disk_io_read': psutil.disk_io_counters().read_bytes if psutil.disk_io_counters() else 0,
                    'disk_io_write': psutil.disk_io_counters().write_bytes if psutil.disk_io_counters() else 0,
                    'network_io_sent': psutil.net_io_counters().bytes_sent,
                    'network_io_recv': psutil.net_io_counters().bytes_recv
                }
                system_metrics.append(metrics)
            except Exception as e:
                print(f"⚠️ System monitoring error: {e}")
            
            time.sleep(1)  # Sample every second
    
    def _calculate_load_test_results(
        self,
        config: LoadTestConfig,
        start_time: datetime,
        end_time: datetime,
        metrics: List[PerformanceMetric],
        system_metrics: List[Dict]
    ) -> LoadTestResult:
        """Calculate comprehensive load test results"""
        if not metrics:
            raise ValueError("No metrics collected during load test")
        
        # Basic counts
        total_requests = len(metrics)
        successful_requests = sum(1 for m in metrics if m.success)
        failed_requests = total_requests - successful_requests
        
        # Response time statistics
        response_times = [m.response_time for m in metrics]
        response_times.sort()
        
        avg_response_time = mean(response_times)
        median_response_time = median(response_times)
        min_response_time = min(response_times)
        max_response_time = max(response_times)
        
        # Percentiles
        def percentile(data, p):
            index = int((len(data) - 1) * p / 100)
            return data[index]
        
        percentile_95 = percentile(response_times, 95)
        percentile_99 = percentile(response_times, 99)
        
        # Throughput
        duration = (end_time - start_time).total_seconds()
        throughput_rps = total_requests / duration if duration > 0 else 0
        
        # System metrics
        peak_memory_mb = max(m['memory_mb'] for m in system_metrics) if system_metrics else 0
        avg_cpu_percent = mean(m['cpu_percent'] for m in system_metrics) if system_metrics else 0
        
        # Error and status code distributions
        error_distribution = {}
        status_code_distribution = {}
        
        for metric in metrics:
            if metric.error_message:
                error_key = metric.error_message[:50]  # Truncate for grouping
                error_distribution[error_key] = error_distribution.get(error_key, 0) + 1
            
            status_code_distribution[metric.status_code] = status_code_distribution.get(metric.status_code, 0) + 1
        
        return LoadTestResult(
            test_name=f"load_test_{config.target_url}",
            config=config,
            start_time=start_time,
            end_time=end_time,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            avg_response_time=avg_response_time,
            median_response_time=median_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            percentile_95=percentile_95,
            percentile_99=percentile_99,
            throughput_rps=throughput_rps,
            peak_memory_mb=peak_memory_mb,
            avg_cpu_percent=avg_cpu_percent,
            metrics=metrics,
            error_distribution=error_distribution,
            status_code_distribution=status_code_distribution
        )
    
    def establish_baseline(self, test_name: str, result: LoadTestResult, version: str = "1.0.0") -> BenchmarkBaseline:
        """
        Establish performance baseline for regression testing
        Task 6.2.1: Performance benchmarking suite
        """
        print(f"\n📊 ESTABLISHING BASELINE: {test_name}")
        print("=" * 60)
        
        error_rate = (result.failed_requests / result.total_requests * 100) if result.total_requests > 0 else 0
        
        baseline = BenchmarkBaseline(
            test_name=test_name,
            date_established=datetime.now(),
            environment="test",
            avg_response_time=result.avg_response_time,
            median_response_time=result.median_response_time,
            percentile_95=result.percentile_95,
            percentile_99=result.percentile_99,
            throughput_rps=result.throughput_rps,
            error_rate_percent=error_rate,
            memory_usage_mb=result.peak_memory_mb,
            cpu_usage_percent=result.avg_cpu_percent,
            version=version,
            configuration={
                'concurrent_users': result.config.concurrent_users,
                'requests_per_user': result.config.requests_per_user,
                'endpoint': result.config.target_url
            }
        )
        
        # Save baseline
        self.baselines[test_name] = asdict(baseline)
        self._save_baselines()
        
        print(f"✅ Baseline established for {test_name}")
        print(f"   Average Response Time: {baseline.avg_response_time:.3f}s")
        print(f"   95th Percentile: {baseline.percentile_95:.3f}s")
        print(f"   Throughput: {baseline.throughput_rps:.2f} RPS")
        print(f"   Error Rate: {baseline.error_rate_percent:.2f}%")
        
        return baseline
    
    def run_regression_test(self, test_name: str, current_result: LoadTestResult, tolerance_percent: float = 10.0) -> Dict[str, Any]:
        """
        Run performance regression test against baseline
        Task 6.2.1: Performance regression testing
        """
        print(f"\n🔍 REGRESSION TEST: {test_name}")
        print("=" * 60)
        
        if test_name not in self.baselines:
            print(f"❌ No baseline found for {test_name}")
            return {
                'status': 'no_baseline',
                'message': f'No baseline established for {test_name}. Run establish_baseline() first.'
            }
        
        baseline_data = self.baselines[test_name]
        baseline = BenchmarkBaseline(**baseline_data)
        
        # Calculate regression metrics
        current_error_rate = (current_result.failed_requests / current_result.total_requests * 100) if current_result.total_requests > 0 else 0
        
        regressions = []
        improvements = []
        
        # Define regression checks
        checks = [
            ('avg_response_time', current_result.avg_response_time, baseline.avg_response_time, 'Average Response Time', 's'),
            ('median_response_time', current_result.median_response_time, baseline.median_response_time, 'Median Response Time', 's'),
            ('percentile_95', current_result.percentile_95, baseline.percentile_95, '95th Percentile', 's'),
            ('percentile_99', current_result.percentile_99, baseline.percentile_99, '99th Percentile', 's'),
            ('throughput_rps', current_result.throughput_rps, baseline.throughput_rps, 'Throughput', ' RPS', True),  # Higher is better
            ('error_rate_percent', current_error_rate, baseline.error_rate_percent, 'Error Rate', '%'),
            ('memory_usage_mb', current_result.peak_memory_mb, baseline.memory_usage_mb, 'Peak Memory Usage', ' MB'),
            ('cpu_usage_percent', current_result.avg_cpu_percent, baseline.cpu_usage_percent, 'CPU Usage', '%')
        ]
        
        for check in checks:
            metric_name, current_value, baseline_value, display_name = check[:4]
            unit = check[4] if len(check) > 4 else ''
            higher_is_better = check[5] if len(check) > 5 else False
            
            if baseline_value == 0:
                continue  # Skip division by zero
            
            if higher_is_better:
                # For metrics where higher is better (e.g., throughput)
                change_percent = ((current_value - baseline_value) / baseline_value) * 100
                if change_percent < -tolerance_percent:  # Significant decrease is bad
                    regressions.append({
                        'metric': metric_name,
                        'display_name': display_name,
                        'baseline_value': baseline_value,
                        'current_value': current_value,
                        'change_percent': change_percent,
                        'unit': unit
                    })
                elif change_percent > tolerance_percent:  # Significant increase is good
                    improvements.append({
                        'metric': metric_name,
                        'display_name': display_name,
                        'baseline_value': baseline_value,
                        'current_value': current_value,
                        'change_percent': change_percent,
                        'unit': unit
                    })
            else:
                # For metrics where lower is better (e.g., response time)
                change_percent = ((current_value - baseline_value) / baseline_value) * 100
                if change_percent > tolerance_percent:  # Significant increase is bad
                    regressions.append({
                        'metric': metric_name,
                        'display_name': display_name,
                        'baseline_value': baseline_value,
                        'current_value': current_value,
                        'change_percent': change_percent,
                        'unit': unit
                    })
                elif change_percent < -tolerance_percent:  # Significant decrease is good
                    improvements.append({
                        'metric': metric_name,
                        'display_name': display_name,
                        'baseline_value': baseline_value,
                        'current_value': current_value,
                        'change_percent': change_percent,
                        'unit': unit
                    })
        
        # Generate report
        status = 'passed' if not regressions else 'failed'
        
        report = {
            'status': status,
            'test_name': test_name,
            'baseline_date': baseline.date_established,
            'current_test_date': datetime.now(),
            'tolerance_percent': tolerance_percent,
            'regressions': regressions,
            'improvements': improvements,
            'summary': {
                'total_checks': len(checks),
                'regressions_count': len(regressions),
                'improvements_count': len(improvements)
            }
        }
        
        # Print results
        self._print_regression_results(report)
        
        # Save regression test results
        self._save_regression_results(report)
        
        return report
    
    def _print_regression_results(self, report: Dict[str, Any]):
        """Print regression test results"""
        print(f"Baseline Date: {report['baseline_date']}")
        print(f"Tolerance: ±{report['tolerance_percent']}%")
        print()
        
        if report['regressions']:
            print("❌ PERFORMANCE REGRESSIONS DETECTED:")
            for regression in report['regressions']:
                print(f"   {regression['display_name']}: "
                      f"{regression['baseline_value']:.3f}{regression['unit']} → "
                      f"{regression['current_value']:.3f}{regression['unit']} "
                      f"({regression['change_percent']:+.1f}%)")
        
        if report['improvements']:
            print("✅ PERFORMANCE IMPROVEMENTS:")
            for improvement in report['improvements']:
                print(f"   {improvement['display_name']}: "
                      f"{improvement['baseline_value']:.3f}{improvement['unit']} → "
                      f"{improvement['current_value']:.3f}{improvement['unit']} "
                      f"({improvement['change_percent']:+.1f}%)")
        
        if not report['regressions'] and not report['improvements']:
            print("✅ Performance within acceptable tolerance")
        
        print(f"\nOverall Status: {'✅ PASSED' if report['status'] == 'passed' else '❌ FAILED'}")
    
    def _load_baselines(self) -> Dict[str, Any]:
        """Load performance baselines from file"""
        try:
            if os.path.exists(self.baselines_file):
                with open(self.baselines_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"⚠️ Could not load baselines: {e}")
        return {}
    
    def _save_baselines(self):
        """Save performance baselines to file"""
        try:
            with open(self.baselines_file, 'w') as f:
                json.dump(self.baselines, f, indent=2, default=str)
        except Exception as e:
            print(f"⚠️ Could not save baselines: {e}")
    
    def _save_load_test_results(self, result: LoadTestResult):
        """Save load test results to file"""
        filename = f"load_test_{result.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            # Convert result to serializable format
            result_data = asdict(result)
            result_data['start_time'] = result.start_time.isoformat()
            result_data['end_time'] = result.end_time.isoformat()
            
            # Convert metrics to serializable format
            result_data['metrics'] = [
                {**asdict(m), 'timestamp': m.timestamp.isoformat()}
                for m in result.metrics
            ]
            
            with open(filepath, 'w') as f:
                json.dump(result_data, f, indent=2, default=str)
            
            print(f"📁 Results saved to: {filepath}")
            
        except Exception as e:
            print(f"⚠️ Could not save results: {e}")
    
    def _save_regression_results(self, report: Dict[str, Any]):
        """Save regression test results to file"""
        filename = f"regression_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            print(f"📁 Regression results saved to: {filepath}")
            
        except Exception as e:
            print(f"⚠️ Could not save regression results: {e}")
    
    def _print_load_test_summary(self, result: LoadTestResult):
        """Print load test summary"""
        print(f"\n📊 LOAD TEST RESULTS")
        print("=" * 60)
        print(f"Test Duration: {(result.end_time - result.start_time).total_seconds():.1f}s")
        print(f"Total Requests: {result.total_requests:,}")
        print(f"Successful: {result.successful_requests:,} ({result.successful_requests/result.total_requests*100:.1f}%)")
        print(f"Failed: {result.failed_requests:,} ({result.failed_requests/result.total_requests*100:.1f}%)")
        print()
        
        print(f"📈 Response Time Metrics:")
        print(f"   Average: {result.avg_response_time:.3f}s")
        print(f"   Median: {result.median_response_time:.3f}s")
        print(f"   Min/Max: {result.min_response_time:.3f}s / {result.max_response_time:.3f}s")
        print(f"   95th Percentile: {result.percentile_95:.3f}s")
        print(f"   99th Percentile: {result.percentile_99:.3f}s")
        print()
        
        print(f"🚀 Throughput: {result.throughput_rps:.2f} RPS")
        print(f"💾 Peak Memory: {result.peak_memory_mb:.1f} MB")
        print(f"🔧 Avg CPU: {result.avg_cpu_percent:.1f}%")
        print()
        
        if result.status_code_distribution:
            print(f"📊 Status Code Distribution:")
            for status_code, count in sorted(result.status_code_distribution.items()):
                percentage = (count / result.total_requests) * 100
                print(f"   {status_code}: {count:,} ({percentage:.1f}%)")
        
        if result.error_distribution:
            print(f"\n❌ Error Distribution:")
            for error, count in sorted(result.error_distribution.items(), key=lambda x: x[1], reverse=True)[:5]:
                percentage = (count / result.failed_requests) * 100 if result.failed_requests > 0 else 0
                print(f"   {error}: {count} ({percentage:.1f}%)")


def create_api_load_test_scenarios() -> List[LoadTestConfig]:
    """
    Create predefined load test scenarios for common API endpoints
    Task 6.2.1: Performance benchmarking suite
    """
    return [
        # Authentication endpoints
        LoadTestConfig(
            target_url="/api/auth/login/",
            concurrent_users=20,
            requests_per_user=50,
            method="POST",
            payload={"username": "testuser", "password": "testpass"},
            headers={"Content-Type": "application/json"}
        ),
        
        # User dashboard
        LoadTestConfig(
            target_url="/api/users/dashboard/",
            concurrent_users=50,
            requests_per_user=100,
            method="GET"
        ),
        
        # Deals listing (organization-scoped)
        LoadTestConfig(
            target_url="/api/deals/",
            concurrent_users=30,
            requests_per_user=75,
            method="GET"
        ),
        
        # Commission calculations
        LoadTestConfig(
            target_url="/api/commission/calculate/",
            concurrent_users=15,
            requests_per_user=25,
            method="POST",
            payload={"deal_id": 1, "amount": 1000.00}
        ),
        
        # High-load scenario for system limits
        LoadTestConfig(
            target_url="/api/health/",
            concurrent_users=100,
            requests_per_user=200,
            method="GET",
            think_time=0.05  # Faster requests
        ),
        
        # Database-intensive scenario
        LoadTestConfig(
            target_url="/api/reports/financial/",
            concurrent_users=10,
            requests_per_user=20,
            method="GET",
            think_time=2.0  # Slower think time for complex queries
        )
    ]


if __name__ == "__main__":
    # Example usage
    framework = PerformanceTestFramework("http://localhost:8000")
    
    # Run a simple load test
    config = LoadTestConfig(
        target_url="/api/health/",
        concurrent_users=10,
        requests_per_user=50
    )
    
    result = framework.run_load_test(config)
    
    # Establish baseline
    baseline = framework.establish_baseline("health_endpoint", result)
    
    # Run regression test
    regression_result = framework.run_regression_test("health_endpoint", result)
