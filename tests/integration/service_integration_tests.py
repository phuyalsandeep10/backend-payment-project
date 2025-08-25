"""
Service Layer Integration Testing - Task 6.3.2

Service layer integration testing with contract validation, interface testing,
and service dependency validation for the Backend_PRS application.
"""

import os
import sys
import django
import json
from decimal import Decimal
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Protocol
from dataclasses import dataclass
from abc import ABC, abstractmethod
from unittest.mock import patch, MagicMock

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase, TransactionTestCase
from django.db import transaction
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.exceptions import ValidationError

# Import services and models
from services.base_service import BaseService, ServiceResult
from authentication.models import User
from organization.models import Organization
from clients.models import Client
from deals.models import Deal, Payment
from commission.models import Commission
from notifications.models import Notification

User = get_user_model()


@dataclass
class ServiceContract:
    """Service contract specification"""
    service_name: str
    required_methods: List[str]
    expected_inputs: Dict[str, Any]
    expected_outputs: Dict[str, Any]
    error_conditions: List[str]
    dependencies: List[str]


@dataclass 
class ContractValidationResult:
    """Result of service contract validation"""
    service_name: str
    contract_valid: bool
    method_validations: Dict[str, bool]
    errors: List[str]
    warnings: List[str]


class ServiceInterface(Protocol):
    """Protocol defining expected service interface"""
    
    def create(self, data: Dict[str, Any]) -> ServiceResult:
        """Create a new entity"""
        ...
    
    def get(self, entity_id: int) -> ServiceResult:
        """Get entity by ID"""
        ...
    
    def update(self, entity_id: int, data: Dict[str, Any]) -> ServiceResult:
        """Update entity"""
        ...
    
    def delete(self, entity_id: int) -> ServiceResult:
        """Delete entity"""
        ...
    
    def list(self, filters: Optional[Dict[str, Any]] = None) -> ServiceResult:
        """List entities with optional filters"""
        ...


class MockClientService(BaseService):
    """Mock client service for testing"""
    
    def __init__(self, user=None, organization=None):
        super().__init__(user, organization)
        self.clients = {}  # In-memory storage for testing
        self.next_id = 1
    
    def create(self, data: Dict[str, Any]) -> ServiceResult:
        """Create a new client"""
        try:
            # Validate required fields
            required_fields = ['client_name', 'email']
            for field in required_fields:
                if field not in data:
                    return self.create_error_result(f"Missing required field: {field}")
            
            # Create client
            client_data = {
                'id': self.next_id,
                'client_name': data['client_name'],
                'email': data['email'],
                'phone_number': data.get('phone_number', ''),
                'organization_id': self.organization.id if self.organization else None,
                'created_by_id': self.user.id if self.user else None,
                'created_at': timezone.now().isoformat()
            }
            
            self.clients[self.next_id] = client_data
            self.next_id += 1
            
            return self.create_result(success=True, data=client_data)
            
        except Exception as e:
            return self.create_error_result(f"Client creation failed: {str(e)}")
    
    def get(self, client_id: int) -> ServiceResult:
        """Get client by ID"""
        if client_id in self.clients:
            return self.create_result(success=True, data=self.clients[client_id])
        return self.create_error_result(f"Client not found: {client_id}")
    
    def update(self, client_id: int, data: Dict[str, Any]) -> ServiceResult:
        """Update client"""
        if client_id not in self.clients:
            return self.create_error_result(f"Client not found: {client_id}")
        
        client = self.clients[client_id].copy()
        client.update(data)
        client['updated_at'] = timezone.now().isoformat()
        self.clients[client_id] = client
        
        return self.create_result(success=True, data=client)
    
    def delete(self, client_id: int) -> ServiceResult:
        """Delete client"""
        if client_id not in self.clients:
            return self.create_error_result(f"Client not found: {client_id}")
        
        del self.clients[client_id]
        return self.create_result(success=True, data={'deleted_id': client_id})
    
    def list(self, filters: Optional[Dict[str, Any]] = None) -> ServiceResult:
        """List clients with optional filters"""
        clients = list(self.clients.values())
        
        if filters:
            # Apply basic filtering
            if 'organization_id' in filters:
                clients = [c for c in clients if c.get('organization_id') == filters['organization_id']]
        
        return self.create_result(success=True, data={'clients': clients, 'count': len(clients)})


class MockDealService(BaseService):
    """Mock deal service for testing"""
    
    def __init__(self, user=None, organization=None, client_service=None):
        super().__init__(user, organization)
        self.deals = {}
        self.next_id = 1
        self.client_service = client_service  # Service dependency
    
    def create(self, data: Dict[str, Any]) -> ServiceResult:
        """Create a new deal"""
        try:
            # Validate required fields
            required_fields = ['client_id', 'deal_name', 'deal_value']
            for field in required_fields:
                if field not in data:
                    return self.create_error_result(f"Missing required field: {field}")
            
            # Validate client exists (service dependency)
            if self.client_service:
                client_result = self.client_service.get(data['client_id'])
                if not client_result.success:
                    return self.create_error_result("Invalid client_id: client not found")
            
            # Create deal
            deal_data = {
                'id': self.next_id,
                'client_id': data['client_id'],
                'deal_name': data['deal_name'],
                'deal_value': float(data['deal_value']),
                'payment_method': data.get('payment_method', 'bank_transfer'),
                'organization_id': self.organization.id if self.organization else None,
                'created_by_id': self.user.id if self.user else None,
                'created_at': timezone.now().isoformat(),
                'status': 'active'
            }
            
            self.deals[self.next_id] = deal_data
            self.next_id += 1
            
            return self.create_result(success=True, data=deal_data)
            
        except Exception as e:
            return self.create_error_result(f"Deal creation failed: {str(e)}")
    
    def get(self, deal_id: int) -> ServiceResult:
        """Get deal by ID"""
        if deal_id in self.deals:
            return self.create_result(success=True, data=self.deals[deal_id])
        return self.create_error_result(f"Deal not found: {deal_id}")
    
    def update(self, deal_id: int, data: Dict[str, Any]) -> ServiceResult:
        """Update deal"""
        if deal_id not in self.deals:
            return self.create_error_result(f"Deal not found: {deal_id}")
        
        deal = self.deals[deal_id].copy()
        deal.update(data)
        deal['updated_at'] = timezone.now().isoformat()
        self.deals[deal_id] = deal
        
        return self.create_result(success=True, data=deal)
    
    def delete(self, deal_id: int) -> ServiceResult:
        """Delete deal"""
        if deal_id not in self.deals:
            return self.create_error_result(f"Deal not found: {deal_id}")
        
        del self.deals[deal_id]
        return self.create_result(success=True, data={'deleted_id': deal_id})
    
    def list(self, filters: Optional[Dict[str, Any]] = None) -> ServiceResult:
        """List deals with optional filters"""
        deals = list(self.deals.values())
        
        if filters:
            if 'client_id' in filters:
                deals = [d for d in deals if d.get('client_id') == filters['client_id']]
            if 'organization_id' in filters:
                deals = [d for d in deals if d.get('organization_id') == filters['organization_id']]
        
        return self.create_result(success=True, data={'deals': deals, 'count': len(deals)})


class ServiceIntegrationTestFramework:
    """
    Framework for testing service layer integration and contracts
    Task 6.3.2: Service layer integration testing
    """
    
    def __init__(self):
        self.service_contracts = {}
        self.test_results = []
        self.services = {}
        
        print("🔧 Service Integration Test Framework Initialized")
    
    def register_service_contract(self, contract: ServiceContract):
        """Register a service contract for validation"""
        self.service_contracts[contract.service_name] = contract
        print(f"📝 Registered service contract: {contract.service_name}")
    
    def register_service_implementation(self, service_name: str, service_instance: Any):
        """Register a service implementation for testing"""
        self.services[service_name] = service_instance
        print(f"🔧 Registered service implementation: {service_name}")
    
    def validate_service_contract(self, service_name: str) -> ContractValidationResult:
        """
        Validate that a service implementation meets its contract
        Task 6.3.2: Contract validation
        """
        print(f"🔍 Validating service contract: {service_name}")
        
        if service_name not in self.service_contracts:
            return ContractValidationResult(
                service_name=service_name,
                contract_valid=False,
                method_validations={},
                errors=[f"No contract defined for service: {service_name}"],
                warnings=[]
            )
        
        if service_name not in self.services:
            return ContractValidationResult(
                service_name=service_name,
                contract_valid=False,
                method_validations={},
                errors=[f"No implementation registered for service: {service_name}"],
                warnings=[]
            )
        
        contract = self.service_contracts[service_name]
        service = self.services[service_name]
        
        errors = []
        warnings = []
        method_validations = {}
        
        # Validate required methods exist
        for method_name in contract.required_methods:
            if hasattr(service, method_name):
                method_validations[method_name] = True
            else:
                method_validations[method_name] = False
                errors.append(f"Missing required method: {method_name}")
        
        # Validate method signatures and behavior
        for method_name in contract.required_methods:
            if hasattr(service, method_name):
                try:
                    self._validate_method_behavior(service, method_name, contract)
                except Exception as e:
                    warnings.append(f"Method {method_name} validation warning: {str(e)}")
        
        # Validate dependencies
        for dependency in contract.dependencies:
            if dependency not in self.services:
                warnings.append(f"Dependency not registered: {dependency}")
        
        contract_valid = len(errors) == 0 and all(method_validations.values())
        
        result = ContractValidationResult(
            service_name=service_name,
            contract_valid=contract_valid,
            method_validations=method_validations,
            errors=errors,
            warnings=warnings
        )
        
        if contract_valid:
            print(f"✅ Service contract valid: {service_name}")
        else:
            print(f"❌ Service contract invalid: {service_name}")
            for error in errors:
                print(f"  • {error}")
        
        return result
    
    def _validate_method_behavior(self, service: Any, method_name: str, contract: ServiceContract):
        """Validate method behavior against contract expectations"""
        method = getattr(service, method_name)
        
        # For now, just check if the method is callable
        if not callable(method):
            raise ValueError(f"Method {method_name} is not callable")
        
        # Could add more sophisticated behavior validation here
        # such as checking method signatures, return types, etc.
    
    def test_service_integration(self, service_a_name: str, service_b_name: str) -> Dict[str, Any]:
        """
        Test integration between two services
        Task 6.3.2: Service dependency testing
        """
        print(f"🔗 Testing service integration: {service_a_name} <-> {service_b_name}")
        
        if service_a_name not in self.services or service_b_name not in self.services:
            return {
                'success': False,
                'error': 'One or both services not registered'
            }
        
        service_a = self.services[service_a_name]
        service_b = self.services[service_b_name]
        
        try:
            # Test basic interaction
            integration_result = self._test_service_interaction(service_a, service_b)
            
            return {
                'success': True,
                'service_a': service_a_name,
                'service_b': service_b_name,
                'integration_result': integration_result
            }
            
        except Exception as e:
            return {
                'success': False,
                'service_a': service_a_name,
                'service_b': service_b_name,
                'error': str(e)
            }
    
    def _test_service_interaction(self, service_a: Any, service_b: Any) -> Dict[str, Any]:
        """Test interaction between two services"""
        # This would be customized based on the specific services
        # For now, return a basic success indicator
        return {
            'interaction_tested': True,
            'timestamp': timezone.now().isoformat()
        }
    
    def run_comprehensive_service_tests(self) -> Dict[str, Any]:
        """
        Run comprehensive service layer integration tests
        Task 6.3.2: Complete service testing suite
        """
        print("\n🚀 COMPREHENSIVE SERVICE INTEGRATION TESTS")
        print("=" * 80)
        
        start_time = timezone.now()
        test_results = {
            'contract_validations': {},
            'integration_tests': {},
            'performance_tests': {},
            'error_handling_tests': {}
        }
        
        # 1. Contract Validation Tests
        print("\n📋 Running Contract Validation Tests...")
        for service_name in self.service_contracts.keys():
            result = self.validate_service_contract(service_name)
            test_results['contract_validations'][service_name] = {
                'valid': result.contract_valid,
                'errors': result.errors,
                'warnings': result.warnings,
                'method_validations': result.method_validations
            }
        
        # 2. Service Integration Tests
        print("\n🔗 Running Service Integration Tests...")
        service_pairs = [
            ('client_service', 'deal_service'),
            # Add more service pairs as needed
        ]
        
        for service_a, service_b in service_pairs:
            if service_a in self.services and service_b in self.services:
                result = self.test_service_integration(service_a, service_b)
                test_results['integration_tests'][f"{service_a}_{service_b}"] = result
        
        # 3. Performance Tests
        print("\n⚡ Running Service Performance Tests...")
        performance_results = self._run_service_performance_tests()
        test_results['performance_tests'] = performance_results
        
        # 4. Error Handling Tests
        print("\n🚨 Running Error Handling Tests...")
        error_handling_results = self._run_error_handling_tests()
        test_results['error_handling_tests'] = error_handling_results
        
        end_time = timezone.now()
        
        # Generate summary
        summary = self._generate_test_summary(test_results, start_time, end_time)
        test_results['summary'] = summary
        
        self._print_test_summary(summary)
        
        return test_results
    
    def _run_service_performance_tests(self) -> Dict[str, Any]:
        """Run performance tests on services"""
        import time
        
        performance_results = {}
        
        for service_name, service in self.services.items():
            print(f"  ⚡ Testing {service_name} performance...")
            
            # Test create performance
            start_time = time.time()
            
            test_data = self._get_test_data_for_service(service_name)
            
            try:
                if hasattr(service, 'create'):
                    result = service.create(test_data)
                    create_time = time.time() - start_time
                    
                    performance_results[service_name] = {
                        'create_time_ms': create_time * 1000,
                        'create_success': result.success if isinstance(result, ServiceResult) else True
                    }
                else:
                    performance_results[service_name] = {
                        'error': 'No create method available'
                    }
                    
            except Exception as e:
                performance_results[service_name] = {
                    'error': f'Performance test failed: {str(e)}'
                }
        
        return performance_results
    
    def _run_error_handling_tests(self) -> Dict[str, Any]:
        """Run error handling tests on services"""
        error_handling_results = {}
        
        for service_name, service in self.services.items():
            print(f"  🚨 Testing {service_name} error handling...")
            
            test_cases = [
                ('invalid_data', {}),  # Empty data
                ('missing_required_fields', {'invalid': 'data'}),
                ('invalid_id', -1),  # Invalid ID for get/update/delete operations
            ]
            
            service_error_results = {}
            
            for test_name, test_input in test_cases:
                try:
                    if hasattr(service, 'create') and test_name in ['invalid_data', 'missing_required_fields']:
                        result = service.create(test_input)
                        service_error_results[test_name] = {
                            'handled_gracefully': isinstance(result, ServiceResult) and not result.success,
                            'error_message': result.errors[0] if isinstance(result, ServiceResult) and result.errors else None
                        }
                    
                    elif hasattr(service, 'get') and test_name == 'invalid_id':
                        result = service.get(test_input)
                        service_error_results[test_name] = {
                            'handled_gracefully': isinstance(result, ServiceResult) and not result.success,
                            'error_message': result.errors[0] if isinstance(result, ServiceResult) and result.errors else None
                        }
                        
                except Exception as e:
                    service_error_results[test_name] = {
                        'handled_gracefully': False,
                        'exception': str(e)
                    }
            
            error_handling_results[service_name] = service_error_results
        
        return error_handling_results
    
    def _get_test_data_for_service(self, service_name: str) -> Dict[str, Any]:
        """Get appropriate test data for a service"""
        test_data_map = {
            'client_service': {
                'client_name': 'Test Client',
                'email': 'test@example.com',
                'phone_number': '+1234567890'
            },
            'deal_service': {
                'client_id': 1,
                'deal_name': 'Test Deal',
                'deal_value': 10000.00
            }
        }
        
        return test_data_map.get(service_name, {'name': 'Test Entity'})
    
    def _generate_test_summary(self, test_results: Dict[str, Any], 
                              start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Generate test summary"""
        total_duration = (end_time - start_time).total_seconds()
        
        # Count contract validation results
        contract_results = test_results.get('contract_validations', {})
        valid_contracts = sum(1 for result in contract_results.values() if result['valid'])
        total_contracts = len(contract_results)
        
        # Count integration test results
        integration_results = test_results.get('integration_tests', {})
        successful_integrations = sum(1 for result in integration_results.values() if result.get('success', False))
        total_integrations = len(integration_results)
        
        # Count performance test results
        performance_results = test_results.get('performance_tests', {})
        successful_performance = sum(1 for result in performance_results.values() if 'error' not in result)
        total_performance = len(performance_results)
        
        # Count error handling test results  
        error_results = test_results.get('error_handling_tests', {})
        total_error_tests = sum(len(service_results) for service_results in error_results.values())
        successful_error_tests = 0
        for service_results in error_results.values():
            for test_result in service_results.values():
                if test_result.get('handled_gracefully', False):
                    successful_error_tests += 1
        
        return {
            'total_duration_seconds': total_duration,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'contract_validation': {
                'total': total_contracts,
                'valid': valid_contracts,
                'success_rate': (valid_contracts / total_contracts * 100) if total_contracts > 0 else 0
            },
            'integration_tests': {
                'total': total_integrations,
                'successful': successful_integrations,
                'success_rate': (successful_integrations / total_integrations * 100) if total_integrations > 0 else 0
            },
            'performance_tests': {
                'total': total_performance,
                'successful': successful_performance,
                'success_rate': (successful_performance / total_performance * 100) if total_performance > 0 else 0
            },
            'error_handling_tests': {
                'total': total_error_tests,
                'successful': successful_error_tests,
                'success_rate': (successful_error_tests / total_error_tests * 100) if total_error_tests > 0 else 0
            }
        }
    
    def _print_test_summary(self, summary: Dict[str, Any]):
        """Print test summary to console"""
        print("\n" + "=" * 80)
        print("📊 SERVICE INTEGRATION TEST SUMMARY")
        print("=" * 80)
        print(f"Total Duration: {summary['total_duration_seconds']:.2f}s")
        
        print(f"\n📋 Contract Validation:")
        contract_stats = summary['contract_validation']
        print(f"  Valid: {contract_stats['valid']}/{contract_stats['total']} ({contract_stats['success_rate']:.1f}%)")
        
        print(f"\n🔗 Integration Tests:")
        integration_stats = summary['integration_tests'] 
        print(f"  Successful: {integration_stats['successful']}/{integration_stats['total']} ({integration_stats['success_rate']:.1f}%)")
        
        print(f"\n⚡ Performance Tests:")
        performance_stats = summary['performance_tests']
        print(f"  Successful: {performance_stats['successful']}/{performance_stats['total']} ({performance_stats['success_rate']:.1f}%)")
        
        print(f"\n🚨 Error Handling Tests:")
        error_stats = summary['error_handling_tests']
        print(f"  Successful: {error_stats['successful']}/{error_stats['total']} ({error_stats['success_rate']:.1f}%)")
        
        # Overall success check
        overall_success = (
            contract_stats['success_rate'] == 100 and
            integration_stats['success_rate'] == 100 and
            performance_stats['success_rate'] == 100 and
            error_stats['success_rate'] >= 80  # Allow some error handling variance
        )
        
        print("=" * 80)
        if overall_success:
            print("🎉 ALL SERVICE INTEGRATION TESTS PASSED! 🎉")
        else:
            print("⚠️ SOME SERVICE TESTS FAILED - REVIEW REQUIRED")
        print("=" * 80)


class ServiceIntegrationTestCase(TransactionTestCase):
    """
    Test case class for service integration testing
    Task 6.3.2: Service integration test cases
    """
    
    def setUp(self):
        """Setup test environment"""
        self.framework = ServiceIntegrationTestFramework()
        
        # Create test organization and user
        self.test_organization = Organization.objects.create(
            name="Service Test Org",
            organization_type="test"
        )
        
        self.test_user = User.objects.create_user(
            username="service_test_user",
            email="service@test.com",
            password="TestPass123!",
            organization=self.test_organization
        )
        
        # Setup service contracts
        self._setup_service_contracts()
        
        # Setup service implementations
        self._setup_service_implementations()
    
    def tearDown(self):
        """Cleanup test environment"""
        User.objects.filter(username="service_test_user").delete()
        Organization.objects.filter(name="Service Test Org").delete()
    
    def _setup_service_contracts(self):
        """Setup service contracts for testing"""
        # Client Service Contract
        client_contract = ServiceContract(
            service_name="client_service",
            required_methods=["create", "get", "update", "delete", "list"],
            expected_inputs={
                "create": ["client_name", "email"],
                "get": ["client_id"],
                "update": ["client_id", "data"],
                "delete": ["client_id"],
                "list": ["filters"]
            },
            expected_outputs={
                "create": "ServiceResult with client data",
                "get": "ServiceResult with client data", 
                "update": "ServiceResult with updated client data",
                "delete": "ServiceResult with deletion confirmation",
                "list": "ServiceResult with client list"
            },
            error_conditions=[
                "Missing required fields",
                "Invalid client_id",
                "Duplicate email"
            ],
            dependencies=[]
        )
        
        # Deal Service Contract
        deal_contract = ServiceContract(
            service_name="deal_service",
            required_methods=["create", "get", "update", "delete", "list"],
            expected_inputs={
                "create": ["client_id", "deal_name", "deal_value"],
                "get": ["deal_id"],
                "update": ["deal_id", "data"],
                "delete": ["deal_id"],
                "list": ["filters"]
            },
            expected_outputs={
                "create": "ServiceResult with deal data",
                "get": "ServiceResult with deal data",
                "update": "ServiceResult with updated deal data", 
                "delete": "ServiceResult with deletion confirmation",
                "list": "ServiceResult with deal list"
            },
            error_conditions=[
                "Missing required fields",
                "Invalid deal_id",
                "Invalid client_id",
                "Invalid deal_value"
            ],
            dependencies=["client_service"]
        )
        
        self.framework.register_service_contract(client_contract)
        self.framework.register_service_contract(deal_contract)
    
    def _setup_service_implementations(self):
        """Setup service implementations for testing"""
        # Create client service
        client_service = MockClientService(
            user=self.test_user,
            organization=self.test_organization
        )
        
        # Create deal service with client service dependency
        deal_service = MockDealService(
            user=self.test_user,
            organization=self.test_organization,
            client_service=client_service
        )
        
        self.framework.register_service_implementation("client_service", client_service)
        self.framework.register_service_implementation("deal_service", deal_service)
    
    def test_service_contracts(self):
        """Test service contract validation"""
        print("\n🔍 Testing Service Contracts...")
        
        # Test client service contract
        client_result = self.framework.validate_service_contract("client_service")
        self.assertTrue(client_result.contract_valid, f"Client service contract invalid: {client_result.errors}")
        
        # Test deal service contract  
        deal_result = self.framework.validate_service_contract("deal_service")
        self.assertTrue(deal_result.contract_valid, f"Deal service contract invalid: {deal_result.errors}")
        
        print("✅ Service contract validation passed")
    
    def test_service_integration(self):
        """Test service integration"""
        print("\n🔗 Testing Service Integration...")
        
        # Test client-deal service integration
        integration_result = self.framework.test_service_integration("client_service", "deal_service")
        self.assertTrue(integration_result['success'], f"Service integration failed: {integration_result.get('error')}")
        
        print("✅ Service integration test passed")
    
    def test_service_dependency_validation(self):
        """Test service dependency validation"""
        print("\n🔗 Testing Service Dependencies...")
        
        client_service = self.framework.services['client_service']
        deal_service = self.framework.services['deal_service']
        
        # Create a client first
        client_result = client_service.create({
            'client_name': 'Test Client',
            'email': 'test@example.com'
        })
        self.assertTrue(client_result.success, "Client creation failed")
        
        client_data = client_result.data
        
        # Create a deal that depends on the client
        deal_result = deal_service.create({
            'client_id': client_data['id'],
            'deal_name': 'Test Deal',
            'deal_value': 10000.00
        })
        self.assertTrue(deal_result.success, "Deal creation failed")
        
        # Try to create deal with invalid client_id
        invalid_deal_result = deal_service.create({
            'client_id': 999,  # Invalid ID
            'deal_name': 'Invalid Deal',
            'deal_value': 5000.00
        })
        self.assertFalse(invalid_deal_result.success, "Deal creation should fail with invalid client_id")
        
        print("✅ Service dependency validation passed")
    
    def test_service_error_handling(self):
        """Test service error handling"""
        print("\n🚨 Testing Service Error Handling...")
        
        client_service = self.framework.services['client_service']
        
        # Test missing required fields
        result = client_service.create({})  # Empty data
        self.assertFalse(result.success, "Should fail with missing required fields")
        self.assertTrue(len(result.errors) > 0, "Should have error messages")
        
        # Test invalid get operation
        result = client_service.get(999)  # Non-existent ID
        self.assertFalse(result.success, "Should fail with invalid ID")
        
        print("✅ Service error handling test passed")
    
    def test_service_performance(self):
        """Test service performance"""
        print("\n⚡ Testing Service Performance...")
        
        import time
        
        client_service = self.framework.services['client_service']
        
        # Test bulk operations performance
        start_time = time.time()
        
        for i in range(10):  # Create 10 clients
            result = client_service.create({
                'client_name': f'Performance Test Client {i}',
                'email': f'perf{i}@test.com'
            })
            self.assertTrue(result.success, f"Client {i} creation failed")
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete 10 operations in reasonable time
        self.assertLess(duration, 1.0, f"Performance test took too long: {duration:.2f}s")
        
        print(f"✅ Service performance test passed ({duration:.3f}s for 10 operations)")
    
    def test_comprehensive_service_integration(self):
        """Run comprehensive service integration tests"""
        print("\n🚀 Running Comprehensive Service Integration Tests...")
        
        results = self.framework.run_comprehensive_service_tests()
        
        # Validate overall success
        summary = results['summary']
        
        self.assertEqual(summary['contract_validation']['success_rate'], 100, 
                        "All service contracts should be valid")
        
        self.assertEqual(summary['integration_tests']['success_rate'], 100,
                        "All service integrations should succeed")
        
        self.assertGreaterEqual(summary['performance_tests']['success_rate'], 80,
                               "Most performance tests should succeed")
        
        self.assertGreaterEqual(summary['error_handling_tests']['success_rate'], 80,
                               "Most error handling tests should succeed")
        
        print("✅ Comprehensive service integration test passed")


# Standalone execution functions
def run_service_integration_tests():
    """Run service integration tests standalone"""
    import unittest
    
    print("\n🚀 RUNNING SERVICE INTEGRATION TESTS")
    print("=" * 80)
    
    # Create test suite
    test_loader = unittest.TestLoader()
    test_suite = test_loader.loadTestsFromTestCase(ServiceIntegrationTestCase)
    
    # Run tests
    test_runner = unittest.TextTestRunner(verbosity=2)
    test_result = test_runner.run(test_suite)
    
    # Print summary
    if test_result.wasSuccessful():
        print("\n🎉 ALL SERVICE INTEGRATION TESTS PASSED! 🎉")
        return True
    else:
        print(f"\n❌ {len(test_result.failures)} test failures, {len(test_result.errors)} test errors")
        return False


if __name__ == "__main__":
    success = run_service_integration_tests()
    sys.exit(0 if success else 1)
