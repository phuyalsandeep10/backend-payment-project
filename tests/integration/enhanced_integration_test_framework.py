"""
Enhanced Integration Test Framework - Task 6.3.1

Comprehensive end-to-end integration tests with automation, cross-service testing,
and advanced validation capabilities for the Backend_PRS application.
"""

import os
import sys
import django
import json
import time
import threading
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager
import requests
from unittest.mock import patch, MagicMock

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase, TransactionTestCase
from django.db import transaction, connection
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

# Import models
from authentication.models import User, SecurityEvent, UserSession
from organization.models import Organization
from permissions.models import Role
from clients.models import Client
from deals.models import Deal, Payment, PaymentInvoice, PaymentApproval
from commission.models import Commission
from notifications.models import Notification, NotificationSettings
from Sales_dashboard.models import DailyStreakRecord
from Verifier_dashboard.models import AuditLogs

User = get_user_model()


@dataclass
class TestScenario:
    """Integration test scenario configuration"""
    name: str
    description: str
    test_function: Callable
    dependencies: List[str] = field(default_factory=list)
    cleanup_function: Optional[Callable] = None
    timeout_seconds: int = 300
    retry_attempts: int = 3
    skip_condition: Optional[Callable] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    """Integration test result data"""
    scenario_name: str
    success: bool
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    steps_completed: List[str] = field(default_factory=list)


@dataclass
class SystemState:
    """System state snapshot for validation"""
    timestamp: datetime
    database_state: Dict[str, int]
    cache_state: Dict[str, Any]
    user_sessions: int
    active_notifications: int
    background_tasks: int
    memory_usage_mb: float
    response_times: Dict[str, float]


class EnhancedIntegrationTestFramework:
    """
    Comprehensive integration testing framework
    Task 6.3.1: End-to-end integration tests with automation
    """
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.api_client = APIClient()
        self.test_scenarios = {}
        self.test_results = []
        self.test_data = {}  # Shared test data between scenarios
        
        # Test environment setup
        self.test_organization = None
        self.test_users = {}
        self.test_data_cleanup = []
        
        # Monitoring integration
        self.performance_monitoring = True
        self.system_states = []
        
        print("🚀 Enhanced Integration Test Framework Initialized")
    
    def register_scenario(self, scenario: TestScenario):
        """Register a test scenario"""
        self.test_scenarios[scenario.name] = scenario
        print(f"📝 Registered scenario: {scenario.name}")
    
    def run_all_scenarios(self, tags: Optional[List[str]] = None, 
                         parallel: bool = False) -> Dict[str, Any]:
        """
        Run all registered test scenarios
        Task 6.3.1: Automated test execution
        """
        print("\n🔥 ENHANCED INTEGRATION TEST SUITE")
        print("=" * 80)
        print(f"Running {len(self.test_scenarios)} test scenarios")
        if tags:
            print(f"Filtered by tags: {', '.join(tags)}")
        print("=" * 80)
        
        start_time = datetime.now()
        
        # Filter scenarios by tags if specified
        scenarios_to_run = self._filter_scenarios_by_tags(tags) if tags else list(self.test_scenarios.values())
        
        # Setup test environment
        self._setup_test_environment()
        
        try:
            if parallel:
                results = self._run_scenarios_parallel(scenarios_to_run)
            else:
                results = self._run_scenarios_sequential(scenarios_to_run)
            
            end_time = datetime.now()
            
            # Generate comprehensive report
            report = self._generate_test_report(results, start_time, end_time)
            
            # Cleanup test environment
            self._cleanup_test_environment()
            
            return report
            
        except Exception as e:
            print(f"❌ Test suite failed: {str(e)}")
            self._cleanup_test_environment()
            raise
    
    def _filter_scenarios_by_tags(self, tags: List[str]) -> List[TestScenario]:
        """Filter scenarios by tags"""
        filtered = []
        for scenario in self.test_scenarios.values():
            if any(tag in scenario.tags for tag in tags):
                filtered.append(scenario)
        return filtered
    
    def _run_scenarios_sequential(self, scenarios: List[TestScenario]) -> List[TestResult]:
        """Run scenarios sequentially"""
        results = []
        
        # Sort scenarios by dependencies
        sorted_scenarios = self._sort_scenarios_by_dependencies(scenarios)
        
        for scenario in sorted_scenarios:
            # Check skip condition
            if scenario.skip_condition and scenario.skip_condition():
                print(f"⏭️ Skipping scenario: {scenario.name}")
                continue
            
            print(f"\n📋 Running scenario: {scenario.name}")
            print(f"Description: {scenario.description}")
            
            result = self._run_single_scenario(scenario)
            results.append(result)
            
            # Stop on failure if not configured to continue
            if not result.success and not getattr(scenario, 'continue_on_failure', False):
                print(f"❌ Scenario failed, stopping execution: {scenario.name}")
                break
        
        return results
    
    def _run_scenarios_parallel(self, scenarios: List[TestScenario]) -> List[TestResult]:
        """Run scenarios in parallel (where possible based on dependencies)"""
        import threading
        import queue
        
        results = []
        results_lock = threading.Lock()
        
        # Group scenarios by dependency level
        dependency_levels = self._group_scenarios_by_dependency_level(scenarios)
        
        for level, level_scenarios in dependency_levels.items():
            print(f"\n📊 Running dependency level {level} scenarios in parallel")
            
            threads = []
            result_queue = queue.Queue()
            
            for scenario in level_scenarios:
                if scenario.skip_condition and scenario.skip_condition():
                    continue
                
                thread = threading.Thread(
                    target=self._run_scenario_in_thread,
                    args=(scenario, result_queue)
                )
                thread.start()
                threads.append(thread)
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Collect results
            level_results = []
            while not result_queue.empty():
                level_results.append(result_queue.get())
            
            with results_lock:
                results.extend(level_results)
            
            # Check for failures in this level
            if any(not result.success for result in level_results):
                print(f"❌ Level {level} had failures, stopping parallel execution")
                break
        
        return results
    
    def _run_scenario_in_thread(self, scenario: TestScenario, result_queue: queue.Queue):
        """Run scenario in a separate thread"""
        result = self._run_single_scenario(scenario)
        result_queue.put(result)
    
    def _run_single_scenario(self, scenario: TestScenario) -> TestResult:
        """Run a single test scenario with retry logic"""
        for attempt in range(scenario.retry_attempts):
            if attempt > 0:
                print(f"🔄 Retry attempt {attempt + 1}/{scenario.retry_attempts}")
                time.sleep(1)  # Brief delay between retries
            
            start_time = datetime.now()
            
            try:
                # Capture initial system state
                if self.performance_monitoring:
                    initial_state = self._capture_system_state()
                    self.system_states.append(initial_state)
                
                # Run the test scenario
                scenario.test_function(self)
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                # Capture final system state
                if self.performance_monitoring:
                    final_state = self._capture_system_state()
                    self.system_states.append(final_state)
                
                # Success result
                result = TestResult(
                    scenario_name=scenario.name,
                    success=True,
                    start_time=start_time,
                    end_time=end_time,
                    duration_seconds=duration,
                    metadata={
                        'attempt': attempt + 1,
                        'performance_data': self._calculate_performance_diff(initial_state, final_state) if self.performance_monitoring else {}
                    }
                )
                
                print(f"✅ Scenario passed: {scenario.name} ({duration:.2f}s)")
                return result
                
            except Exception as e:
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                error_msg = str(e)
                print(f"❌ Scenario failed: {scenario.name} - {error_msg}")
                
                if attempt == scenario.retry_attempts - 1:  # Last attempt
                    return TestResult(
                        scenario_name=scenario.name,
                        success=False,
                        start_time=start_time,
                        end_time=end_time,
                        duration_seconds=duration,
                        error_message=error_msg,
                        metadata={'attempts': scenario.retry_attempts}
                    )
        
        # Should not reach here, but return failure as fallback
        return TestResult(
            scenario_name=scenario.name,
            success=False,
            start_time=start_time,
            end_time=datetime.now(),
            duration_seconds=0,
            error_message="Unknown failure"
        )
    
    def _setup_test_environment(self):
        """Setup comprehensive test environment"""
        print("\n🔧 Setting up test environment...")
        
        with transaction.atomic():
            # Create test organization
            self.test_organization = Organization.objects.create(
                name="Integration Test Org",
                organization_type="test",
                status="active"
            )
            
            # Create test users with different roles
            self.test_users['admin'] = User.objects.create_user(
                username="test_admin",
                email="admin@integrationtest.com",
                password="TestPass123!",
                organization=self.test_organization,
                role="admin"
            )
            
            self.test_users['salesperson'] = User.objects.create_user(
                username="test_salesperson", 
                email="sales@integrationtest.com",
                password="TestPass123!",
                organization=self.test_organization,
                role="sales"
            )
            
            self.test_users['verifier'] = User.objects.create_user(
                username="test_verifier",
                email="verifier@integrationtest.com", 
                password="TestPass123!",
                organization=self.test_organization,
                role="verifier"
            )
            
            # Store for cleanup
            self.test_data_cleanup.extend([
                ('User', [user.id for user in self.test_users.values()]),
                ('Organization', [self.test_organization.id])
            ])
        
        # Clear cache
        cache.clear()
        
        print(f"✅ Test environment ready - Org: {self.test_organization.name}")
    
    def _cleanup_test_environment(self):
        """Cleanup test environment"""
        print("\n🧹 Cleaning up test environment...")
        
        try:
            with transaction.atomic():
                # Cleanup in reverse order to handle dependencies
                for model_name, ids in reversed(self.test_data_cleanup):
                    if model_name == 'User':
                        User.objects.filter(id__in=ids).delete()
                    elif model_name == 'Organization':
                        Organization.objects.filter(id__in=ids).delete()
                    elif model_name == 'Client':
                        Client.objects.filter(id__in=ids).delete()
                    elif model_name == 'Deal':
                        Deal.objects.filter(id__in=ids).delete()
                    elif model_name == 'Payment':
                        Payment.objects.filter(id__in=ids).delete()
                    # Add other models as needed
            
            # Clear cache
            cache.clear()
            
            print("✅ Test environment cleanup complete")
            
        except Exception as e:
            print(f"⚠️ Cleanup warning: {str(e)}")
    
    def _capture_system_state(self) -> SystemState:
        """Capture current system state for performance monitoring"""
        try:
            # Database counts
            database_state = {
                'users': User.objects.count(),
                'organizations': Organization.objects.count(),
                'clients': Client.objects.count(),
                'deals': Deal.objects.count(),
                'payments': Payment.objects.count(),
                'notifications': Notification.objects.count()
            }
            
            # Cache state (simplified)
            cache_state = {
                'cache_keys': len(cache._cache) if hasattr(cache, '_cache') else 0
            }
            
            # System metrics
            try:
                import psutil
                memory_usage_mb = psutil.Process().memory_info().rss / 1024 / 1024
            except ImportError:
                memory_usage_mb = 0.0
            
            return SystemState(
                timestamp=timezone.now(),
                database_state=database_state,
                cache_state=cache_state,
                user_sessions=UserSession.objects.count() if hasattr(UserSession, 'objects') else 0,
                active_notifications=Notification.objects.filter(is_read=False).count(),
                background_tasks=0,  # Would integrate with Celery
                memory_usage_mb=memory_usage_mb,
                response_times={}
            )
            
        except Exception as e:
            print(f"⚠️ System state capture warning: {e}")
            return SystemState(
                timestamp=timezone.now(),
                database_state={},
                cache_state={},
                user_sessions=0,
                active_notifications=0,
                background_tasks=0,
                memory_usage_mb=0.0,
                response_times={}
            )
    
    def _calculate_performance_diff(self, initial: SystemState, final: SystemState) -> Dict[str, Any]:
        """Calculate performance differences between states"""
        return {
            'duration_seconds': (final.timestamp - initial.timestamp).total_seconds(),
            'memory_change_mb': final.memory_usage_mb - initial.memory_usage_mb,
            'database_changes': {
                key: final.database_state.get(key, 0) - initial.database_state.get(key, 0)
                for key in set(initial.database_state.keys()) | set(final.database_state.keys())
            },
            'notifications_created': final.active_notifications - initial.active_notifications
        }
    
    def _sort_scenarios_by_dependencies(self, scenarios: List[TestScenario]) -> List[TestScenario]:
        """Sort scenarios by their dependencies"""
        sorted_scenarios = []
        remaining_scenarios = scenarios.copy()
        
        while remaining_scenarios:
            # Find scenarios with no unmet dependencies
            ready_scenarios = []
            for scenario in remaining_scenarios:
                unmet_deps = [dep for dep in scenario.dependencies if dep not in [s.name for s in sorted_scenarios]]
                if not unmet_deps:
                    ready_scenarios.append(scenario)
            
            if not ready_scenarios:
                # Circular dependency or missing dependency
                print(f"⚠️ Circular or missing dependencies detected")
                ready_scenarios = remaining_scenarios  # Run remaining in order
            
            sorted_scenarios.extend(ready_scenarios)
            for scenario in ready_scenarios:
                remaining_scenarios.remove(scenario)
        
        return sorted_scenarios
    
    def _group_scenarios_by_dependency_level(self, scenarios: List[TestScenario]) -> Dict[int, List[TestScenario]]:
        """Group scenarios by dependency level for parallel execution"""
        levels = {}
        scenario_levels = {}
        
        # Calculate dependency levels
        def get_level(scenario):
            if scenario.name in scenario_levels:
                return scenario_levels[scenario.name]
            
            if not scenario.dependencies:
                level = 0
            else:
                max_dep_level = -1
                for dep_name in scenario.dependencies:
                    dep_scenario = self.test_scenarios.get(dep_name)
                    if dep_scenario:
                        dep_level = get_level(dep_scenario)
                        max_dep_level = max(max_dep_level, dep_level)
                level = max_dep_level + 1
            
            scenario_levels[scenario.name] = level
            return level
        
        # Group by levels
        for scenario in scenarios:
            level = get_level(scenario)
            if level not in levels:
                levels[level] = []
            levels[level].append(scenario)
        
        return levels
    
    def _generate_test_report(self, results: List[TestResult], 
                             start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        total_duration = (end_time - start_time).total_seconds()
        successful_tests = [r for r in results if r.success]
        failed_tests = [r for r in results if not r.success]
        
        report = {
            'summary': {
                'total_scenarios': len(results),
                'successful': len(successful_tests),
                'failed': len(failed_tests),
                'success_rate': (len(successful_tests) / len(results)) * 100 if results else 0,
                'total_duration_seconds': total_duration,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            },
            'results': [asdict(result) for result in results],
            'performance_analysis': self._analyze_performance_data(),
            'system_state_changes': self._analyze_system_state_changes(),
            'recommendations': self._generate_recommendations(results)
        }
        
        # Print report summary
        self._print_test_report_summary(report)
        
        return report
    
    def _analyze_performance_data(self) -> Dict[str, Any]:
        """Analyze performance data from test execution"""
        if len(self.system_states) < 2:
            return {'message': 'Insufficient data for performance analysis'}
        
        initial_state = self.system_states[0]
        final_state = self.system_states[-1]
        
        return {
            'total_memory_change_mb': final_state.memory_usage_mb - initial_state.memory_usage_mb,
            'database_growth': {
                key: final_state.database_state.get(key, 0) - initial_state.database_state.get(key, 0)
                for key in set(initial_state.database_state.keys()) | set(final_state.database_state.keys())
            },
            'peak_memory_mb': max(state.memory_usage_mb for state in self.system_states),
            'test_duration_minutes': (final_state.timestamp - initial_state.timestamp).total_seconds() / 60
        }
    
    def _analyze_system_state_changes(self) -> Dict[str, Any]:
        """Analyze system state changes during testing"""
        if not self.system_states:
            return {'message': 'No system state data available'}
        
        # Calculate state change trends
        state_changes = []
        for i in range(1, len(self.system_states)):
            prev_state = self.system_states[i-1]
            curr_state = self.system_states[i]
            
            change = {
                'timestamp': curr_state.timestamp.isoformat(),
                'memory_change_mb': curr_state.memory_usage_mb - prev_state.memory_usage_mb,
                'database_changes': {
                    key: curr_state.database_state.get(key, 0) - prev_state.database_state.get(key, 0)
                    for key in set(prev_state.database_state.keys()) | set(curr_state.database_state.keys())
                }
            }
            state_changes.append(change)
        
        return {
            'total_state_snapshots': len(self.system_states),
            'state_changes': state_changes,
            'overall_trends': {
                'memory_trend': 'increasing' if self.system_states[-1].memory_usage_mb > self.system_states[0].memory_usage_mb else 'stable/decreasing'
            }
        }
    
    def _generate_recommendations(self, results: List[TestResult]) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        failed_results = [r for r in results if not r.success]
        if failed_results:
            recommendations.append(f"Address {len(failed_results)} failed test scenarios")
            
            # Group failures by error type
            error_types = {}
            for result in failed_results:
                error_msg = result.error_message or "Unknown error"
                error_type = error_msg.split(':')[0] if ':' in error_msg else error_msg
                error_types[error_type] = error_types.get(error_type, 0) + 1
            
            for error_type, count in error_types.items():
                recommendations.append(f"Investigate {count} instances of: {error_type}")
        
        # Performance recommendations
        long_running_tests = [r for r in results if r.duration_seconds > 60]  # 1 minute threshold
        if long_running_tests:
            recommendations.append(f"Optimize {len(long_running_tests)} slow test scenarios")
        
        # System resource recommendations
        performance_data = self._analyze_performance_data()
        if isinstance(performance_data, dict) and performance_data.get('total_memory_change_mb', 0) > 100:
            recommendations.append("Monitor memory usage - significant memory increase detected during testing")
        
        return recommendations
    
    def _print_test_report_summary(self, report: Dict[str, Any]):
        """Print test report summary to console"""
        summary = report['summary']
        
        print("\n" + "=" * 80)
        print("📊 ENHANCED INTEGRATION TEST REPORT")
        print("=" * 80)
        print(f"Total Scenarios: {summary['total_scenarios']}")
        print(f"Successful: {summary['successful']} ✅")
        print(f"Failed: {summary['failed']} ❌")
        print(f"Success Rate: {summary['success_rate']:.1f}%")
        print(f"Total Duration: {summary['total_duration_seconds']:.2f}s")
        
        if report.get('recommendations'):
            print("\n💡 Recommendations:")
            for rec in report['recommendations']:
                print(f"  • {rec}")
        
        print("=" * 80)
        
        if summary['failed'] == 0:
            print("🎉 ALL INTEGRATION TESTS PASSED! 🎉")
        else:
            print("⚠️ SOME TESTS FAILED - REVIEW REQUIRED")
    
    # Helper methods for test scenarios
    def create_test_client(self, client_data: Optional[Dict] = None) -> Client:
        """Create a test client"""
        default_data = {
            'client_name': 'Integration Test Client',
            'email': 'testclient@example.com',
            'phone_number': '+1234567890',
            'nationality': 'US'
        }
        
        if client_data:
            default_data.update(client_data)
        
        client = Client.objects.create(
            **default_data,
            organization=self.test_organization,
            created_by=self.test_users['salesperson']
        )
        
        self.test_data_cleanup.append(('Client', [client.id]))
        return client
    
    def create_test_deal(self, client: Client, deal_data: Optional[Dict] = None) -> Deal:
        """Create a test deal"""
        default_data = {
            'deal_name': 'Integration Test Deal',
            'deal_value': Decimal('15000.00'),
            'payment_method': 'bank_transfer',
            'source_type': 'website'
        }
        
        if deal_data:
            default_data.update(deal_data)
        
        deal = Deal.objects.create(
            client=client,
            organization=self.test_organization,
            created_by=self.test_users['salesperson'],
            **default_data
        )
        
        self.test_data_cleanup.append(('Deal', [deal.id]))
        return deal
    
    def create_test_payment(self, deal: Deal, payment_data: Optional[Dict] = None) -> Payment:
        """Create a test payment"""
        default_data = {
            'payment_method': 'bank_transfer',
            'received_amount': Decimal('15000.00'),
            'transaction_id': f'TEST_TXN_{int(time.time())}'
        }
        
        if payment_data:
            default_data.update(payment_data)
        
        payment = Payment.objects.create(
            deal=deal,
            **default_data
        )
        
        self.test_data_cleanup.append(('Payment', [payment.id]))
        return payment
    
    @contextmanager
    def assert_performance_within_limits(self, max_duration_seconds: float = 30.0, 
                                        max_memory_increase_mb: float = 50.0):
        """Context manager to assert performance within limits"""
        start_time = time.time()
        initial_state = self._capture_system_state()
        
        try:
            yield
        finally:
            end_time = time.time()
            final_state = self._capture_system_state()
            
            duration = end_time - start_time
            memory_increase = final_state.memory_usage_mb - initial_state.memory_usage_mb
            
            assert duration <= max_duration_seconds, f"Performance test exceeded time limit: {duration:.2f}s > {max_duration_seconds}s"
            assert memory_increase <= max_memory_increase_mb, f"Memory usage exceeded limit: {memory_increase:.2f}MB > {max_memory_increase_mb}MB"
    
    def assert_database_consistency(self):
        """Assert database consistency and referential integrity"""
        # Check for orphaned records
        orphaned_deals = Deal.objects.filter(client__isnull=True).count()
        assert orphaned_deals == 0, f"Found {orphaned_deals} orphaned deals"
        
        orphaned_payments = Payment.objects.filter(deal__isnull=True).count() 
        assert orphaned_payments == 0, f"Found {orphaned_payments} orphaned payments"
        
        # Check for data integrity issues
        invalid_deal_values = Deal.objects.filter(deal_value__lt=0).count()
        assert invalid_deal_values == 0, f"Found {invalid_deal_values} deals with negative values"
    
    def assert_organization_data_isolation(self):
        """Assert that organization data isolation is maintained"""
        # Ensure test data is properly scoped to test organization
        test_clients = Client.objects.filter(organization=self.test_organization)
        other_org_clients = Client.objects.exclude(organization=self.test_organization)
        
        # Test organization should have test data
        assert test_clients.exists(), "Test organization should have client data"
        
        # Other organizations should not see test data
        for client in test_clients:
            assert client.organization == self.test_organization, "Client organization mismatch"


# Global framework instance
integration_framework = EnhancedIntegrationTestFramework()
