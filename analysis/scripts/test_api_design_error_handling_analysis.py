#!/usr/bin/env python3
"""
API Design and Error Handling Analysis
Comprehensive analysis of API endpoints, error handling consistency, and documentation.

This script analyzes:
1. API endpoint functionality and response formats
2. Error handling consistency and user experience
3. HTTP status code usage and error messages
4. API documentation and swagger integration

Requirements: 5.3, 5.2, 6.2
"""

import os
import sys
import django
import json
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import re

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase, Client
from django.urls import reverse, resolve
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework.response import Response
from django.http import JsonResponse, HttpResponse
from django.template.response import TemplateResponse

# Import models and utilities
from authentication.models import User
from organization.models import Organization
from clients.models import Client
from deals.models import Deal, Payment
from permissions.models import Role, Permission
from core_config.error_handling import StandardErrorResponse
from core_config.error_response import StandardErrorResponse as ErrorResponse

@dataclass
class APIEndpointAnalysis:
    """Data structure for API endpoint analysis results"""
    endpoint: str
    method: str
    view_name: str
    status_code: int
    response_type: str
    content_type: str
    has_error_handling: bool
    error_format_consistent: bool
    uses_standard_status_codes: bool
    has_validation: bool
    response_structure: Dict[str, Any]
    error_messages: List[str]
    security_headers: Dict[str, str]
    performance_metrics: Dict[str, Any]

@dataclass
class ErrorHandlingAnalysis:
    """Data structure for error handling analysis results"""
    error_type: str
    endpoint: str
    status_code: int
    error_format: str
    message_quality: str
    sensitive_data_exposed: bool
    consistent_with_standard: bool
    user_friendly: bool
    actionable_message: bool

@dataclass
class DocumentationAnalysis:
    """Data structure for API documentation analysis"""
    swagger_available: bool
    redoc_available: bool
    endpoint_documented: bool
    parameters_documented: bool
    responses_documented: bool
    examples_provided: bool
    error_responses_documented: bool
    authentication_documented: bool

class APIDesignErrorHandlingAnalyzer:
    """
    Comprehensive analyzer for API design and error handling
    """
    
    def __init__(self):
        self.client = APIClient()
        self.django_client = Client()
        self.results = {
            'endpoint_analysis': [],
            'error_handling_analysis': [],
            'documentation_analysis': {},
            'consistency_issues': [],
            'security_issues': [],
            'performance_issues': [],
            'recommendations': []
        }
        self.test_user = None
        self.test_organization = None
        
    def setup_test_data(self):
        """Setup test data for analysis"""
        try:
            # Create test organization
            self.test_organization, created = Organization.objects.get_or_create(
                name="Test Organization",
                defaults={'description': 'Test organization for API analysis'}
            )
            
            # Create test user
            self.test_user, created = User.objects.get_or_create(
                email="test_api_user@example.com",
                defaults={
                    'username': 'test_api_user',
                    'first_name': 'Test',
                    'last_name': 'User',
                    'organization': self.test_organization,
                    'is_active': True
                }
            )
            
            if created:
                self.test_user.set_password('TestPassword123!')
                self.test_user.save()
            
            # Create test role and permissions
            role, created = Role.objects.get_or_create(
                name="API Test Role",
                defaults={'description': 'Role for API testing'}
            )
            
            if created:
                # Add basic permissions
                permissions = Permission.objects.filter(
                    codename__in=['view_client', 'add_client', 'view_deal', 'add_deal']
                )
                role.permissions.set(permissions)
            
            self.test_user.role = role
            self.test_user.save()
            
            print(f"✓ Test data setup complete - User: {self.test_user.email}")
            
        except Exception as e:
            print(f"✗ Error setting up test data: {str(e)}")
            
    def authenticate_user(self):
        """Authenticate test user for API calls"""
        try:
            self.client.force_authenticate(user=self.test_user)
            print("✓ User authenticated for API testing")
            return True
        except Exception as e:
            print(f"✗ Authentication failed: {str(e)}")
            return False
    
    def analyze_api_endpoints(self):
        """Analyze all API endpoints for design consistency and functionality"""
        print("\n=== API Endpoint Analysis ===")
        
        # Define key endpoints to test
        endpoints_to_test = [
            # Authentication endpoints
            {'url': '/api/auth/login/', 'method': 'POST', 'name': 'login'},
            {'url': '/api/auth/logout/', 'method': 'POST', 'name': 'logout'},
            {'url': '/api/auth/users/', 'method': 'GET', 'name': 'user-list'},
            {'url': '/api/auth/profile/', 'method': 'GET', 'name': 'user-profile'},
            
            # Client endpoints
            {'url': '/api/clients/', 'method': 'GET', 'name': 'client-list'},
            {'url': '/api/clients/', 'method': 'POST', 'name': 'client-create'},
            
            # Deal endpoints
            {'url': '/api/deals/', 'method': 'GET', 'name': 'deal-list'},
            {'url': '/api/deals/', 'method': 'POST', 'name': 'deal-create'},
            
            # System endpoints
            {'url': '/api/health/', 'method': 'GET', 'name': 'health-check'},
            
            # Documentation endpoints
            {'url': '/swagger/', 'method': 'GET', 'name': 'swagger-ui'},
            {'url': '/redoc/', 'method': 'GET', 'name': 'redoc-ui'},
        ]
        
        for endpoint_config in endpoints_to_test:
            analysis = self._analyze_single_endpoint(endpoint_config)
            self.results['endpoint_analysis'].append(analysis)
            
        self._analyze_endpoint_consistency()
        
    def _analyze_single_endpoint(self, endpoint_config: Dict[str, str]) -> APIEndpointAnalysis:
        """Analyze a single API endpoint"""
        url = endpoint_config['url']
        method = endpoint_config['method']
        name = endpoint_config['name']
        
        print(f"Analyzing {method} {url}")
        
        try:
            # Make request based on method
            if method == 'GET':
                response = self.client.get(url)
            elif method == 'POST':
                # Use appropriate test data for POST requests
                test_data = self._get_test_data_for_endpoint(name)
                response = self.client.post(url, test_data, format='json')
            elif method == 'PUT':
                test_data = self._get_test_data_for_endpoint(name)
                response = self.client.put(url, test_data, format='json')
            elif method == 'DELETE':
                response = self.client.delete(url)
            else:
                response = self.client.get(url)  # Default to GET
            
            # Analyze response
            analysis = APIEndpointAnalysis(
                endpoint=url,
                method=method,
                view_name=name,
                status_code=response.status_code,
                response_type=type(response).__name__,
                content_type=response.get('Content-Type', ''),
                has_error_handling=self._check_error_handling(response),
                error_format_consistent=self._check_error_format_consistency(response),
                uses_standard_status_codes=self._check_standard_status_codes(response),
                has_validation=self._check_validation(response),
                response_structure=self._analyze_response_structure(response),
                error_messages=self._extract_error_messages(response),
                security_headers=self._analyze_security_headers(response),
                performance_metrics=self._measure_performance_metrics(url, method)
            )
            
            return analysis
            
        except Exception as e:
            print(f"  ✗ Error analyzing {url}: {str(e)}")
            return APIEndpointAnalysis(
                endpoint=url,
                method=method,
                view_name=name,
                status_code=500,
                response_type="Error",
                content_type="",
                has_error_handling=False,
                error_format_consistent=False,
                uses_standard_status_codes=False,
                has_validation=False,
                response_structure={},
                error_messages=[str(e)],
                security_headers={},
                performance_metrics={}
            )
    
    def _get_test_data_for_endpoint(self, endpoint_name: str) -> Dict[str, Any]:
        """Get appropriate test data for different endpoints"""
        test_data_map = {
            'login': {
                'email': 'test_api_user@example.com',
                'password': 'TestPassword123!'
            },
            'client-create': {
                'client_name': 'Test API Client',
                'email': 'testclient@example.com',
                'phone': '+1234567890',
                'address': '123 Test Street'
            },
            'deal-create': {
                'deal_name': 'Test API Deal',
                'deal_value': '10000.00',
                'payment_method': 'bank_transfer',
                'source_type': 'referral'
            }
        }
        
        return test_data_map.get(endpoint_name, {})
    
    def _check_error_handling(self, response) -> bool:
        """Check if endpoint has proper error handling"""
        if response.status_code >= 400:
            try:
                data = response.json() if hasattr(response, 'json') else {}
                return 'error' in data or 'message' in data or 'detail' in data
            except:
                return False
        return True
    
    def _check_error_format_consistency(self, response) -> bool:
        """Check if error format follows standard pattern"""
        if response.status_code >= 400:
            try:
                data = response.json() if hasattr(response, 'json') else {}
                
                # Check for standard error format
                if 'error' in data:
                    error_obj = data['error']
                    return isinstance(error_obj, dict) and 'code' in error_obj and 'message' in error_obj
                
                # Check for DRF standard format
                return 'detail' in data or any(key in data for key in ['message', 'errors'])
                
            except:
                return False
        return True
    
    def _check_standard_status_codes(self, response) -> bool:
        """Check if endpoint uses appropriate HTTP status codes"""
        status_code = response.status_code
        
        # Define expected status codes for different scenarios
        valid_codes = [
            200, 201, 202, 204,  # Success codes
            400, 401, 403, 404, 405, 409, 422, 429,  # Client error codes
            500, 502, 503, 504  # Server error codes
        ]
        
        return status_code in valid_codes
    
    def _check_validation(self, response) -> bool:
        """Check if endpoint has proper input validation"""
        if response.status_code == 400:
            try:
                data = response.json() if hasattr(response, 'json') else {}
                # Look for validation error indicators
                validation_indicators = ['field', 'validation', 'required', 'invalid']
                response_str = str(data).lower()
                return any(indicator in response_str for indicator in validation_indicators)
            except:
                return False
        return True
    
    def _analyze_response_structure(self, response) -> Dict[str, Any]:
        """Analyze the structure of the response"""
        try:
            if hasattr(response, 'json'):
                data = response.json()
                return {
                    'has_data': bool(data),
                    'is_dict': isinstance(data, dict),
                    'is_list': isinstance(data, list),
                    'keys': list(data.keys()) if isinstance(data, dict) else [],
                    'length': len(data) if isinstance(data, (list, dict)) else 0
                }
            else:
                return {
                    'has_data': bool(response.content),
                    'content_length': len(response.content) if response.content else 0
                }
        except:
            return {'error': 'Could not parse response structure'}
    
    def _extract_error_messages(self, response) -> List[str]:
        """Extract error messages from response"""
        messages = []
        
        if response.status_code >= 400:
            try:
                data = response.json() if hasattr(response, 'json') else {}
                
                # Extract messages from different formats
                if 'error' in data and isinstance(data['error'], dict):
                    if 'message' in data['error']:
                        messages.append(data['error']['message'])
                
                if 'detail' in data:
                    messages.append(str(data['detail']))
                
                if 'message' in data:
                    messages.append(str(data['message']))
                
                # Extract field-specific errors
                for key, value in data.items():
                    if isinstance(value, list) and key not in ['error', 'detail', 'message']:
                        messages.extend([str(v) for v in value])
                
            except:
                messages.append("Could not parse error message")
        
        return messages
    
    def _analyze_security_headers(self, response) -> Dict[str, str]:
        """Analyze security headers in response"""
        security_headers = {}
        
        important_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'Referrer-Policy'
        ]
        
        for header in important_headers:
            if header in response:
                security_headers[header] = response[header]
        
        return security_headers
    
    def _measure_performance_metrics(self, url: str, method: str) -> Dict[str, Any]:
        """Measure basic performance metrics for endpoint"""
        import time
        
        try:
            start_time = time.time()
            
            # Make a simple request to measure response time
            if method == 'GET':
                response = self.client.get(url)
            else:
                response = self.client.get(url)  # Default to GET for performance test
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            return {
                'response_time_ms': round(response_time, 2),
                'content_length': len(response.content) if response.content else 0,
                'status_code': response.status_code
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_error_handling_patterns(self):
        """Analyze error handling patterns across the application"""
        print("\n=== Error Handling Pattern Analysis ===")
        
        # Test different error scenarios
        error_scenarios = [
            {
                'name': 'Unauthenticated Access',
                'setup': lambda: self.client.force_authenticate(user=None),
                'test': lambda: self.client.get('/api/clients/'),
                'expected_status': 401
            },
            {
                'name': 'Invalid Data Validation',
                'setup': lambda: self.client.force_authenticate(user=self.test_user),
                'test': lambda: self.client.post('/api/clients/', {'invalid': 'data'}, format='json'),
                'expected_status': 400
            },
            {
                'name': 'Not Found Resource',
                'setup': lambda: self.client.force_authenticate(user=self.test_user),
                'test': lambda: self.client.get('/api/clients/99999/'),
                'expected_status': 404
            },
            {
                'name': 'Method Not Allowed',
                'setup': lambda: self.client.force_authenticate(user=self.test_user),
                'test': lambda: self.client.patch('/api/health/'),
                'expected_status': 405
            }
        ]
        
        for scenario in error_scenarios:
            print(f"Testing: {scenario['name']}")
            
            try:
                # Setup scenario
                scenario['setup']()
                
                # Execute test
                response = scenario['test']()
                
                # Analyze error response
                analysis = ErrorHandlingAnalysis(
                    error_type=scenario['name'],
                    endpoint="Various",
                    status_code=response.status_code,
                    error_format=self._analyze_error_format(response),
                    message_quality=self._assess_message_quality(response),
                    sensitive_data_exposed=self._check_sensitive_data_exposure(response),
                    consistent_with_standard=self._check_consistency_with_standard(response),
                    user_friendly=self._assess_user_friendliness(response),
                    actionable_message=self._check_actionable_message(response)
                )
                
                self.results['error_handling_analysis'].append(analysis)
                
                # Check if status code matches expected
                if response.status_code == scenario['expected_status']:
                    print(f"  ✓ Correct status code: {response.status_code}")
                else:
                    print(f"  ✗ Expected {scenario['expected_status']}, got {response.status_code}")
                    
            except Exception as e:
                print(f"  ✗ Error in scenario: {str(e)}")
    
    def _analyze_error_format(self, response) -> str:
        """Analyze the format of error response"""
        try:
            data = response.json() if hasattr(response, 'json') else {}
            
            if 'error' in data and isinstance(data['error'], dict):
                if all(key in data['error'] for key in ['code', 'message']):
                    return "StandardErrorResponse"
            
            if 'detail' in data:
                return "DRF_Standard"
            
            if any(key in data for key in ['message', 'errors']):
                return "Custom_Format"
            
            return "Unknown_Format"
            
        except:
            return "Non_JSON"
    
    def _assess_message_quality(self, response) -> str:
        """Assess the quality of error messages"""
        try:
            messages = self._extract_error_messages(response)
            
            if not messages:
                return "No_Message"
            
            # Check for generic vs specific messages
            generic_patterns = ['error', 'failed', 'invalid', 'bad request']
            specific_indicators = ['field', 'required', 'format', 'length']
            
            message_text = ' '.join(messages).lower()
            
            has_specific = any(indicator in message_text for indicator in specific_indicators)
            is_generic = any(pattern in message_text for pattern in generic_patterns)
            
            if has_specific:
                return "Specific"
            elif is_generic:
                return "Generic"
            else:
                return "Custom"
                
        except:
            return "Parse_Error"
    
    def _check_sensitive_data_exposure(self, response) -> bool:
        """Check if error response exposes sensitive data"""
        try:
            content = str(response.content)
            
            # Patterns that might indicate sensitive data exposure
            sensitive_patterns = [
                r'password',
                r'secret',
                r'token',
                r'key',
                r'/home/',
                r'/var/',
                r'Traceback',
                r'File "/',
                r'line \d+',
                r'postgresql://',
                r'mysql://',
                r'sqlite:///'
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            return False
            
        except:
            return False
    
    def _check_consistency_with_standard(self, response) -> bool:
        """Check if error response is consistent with StandardErrorResponse"""
        try:
            data = response.json() if hasattr(response, 'json') else {}
            
            # Check for StandardErrorResponse format
            if 'error' in data and isinstance(data['error'], dict):
                error_obj = data['error']
                required_fields = ['code', 'message']
                return all(field in error_obj for field in required_fields)
            
            return False
            
        except:
            return False
    
    def _assess_user_friendliness(self, response) -> bool:
        """Assess if error messages are user-friendly"""
        try:
            messages = self._extract_error_messages(response)
            
            if not messages:
                return False
            
            # Check for technical jargon that users might not understand
            technical_terms = [
                'null constraint',
                'foreign key',
                'serializer',
                'queryset',
                'traceback',
                'exception',
                'stack trace'
            ]
            
            message_text = ' '.join(messages).lower()
            
            # User-friendly messages should avoid technical jargon
            has_technical_jargon = any(term in message_text for term in technical_terms)
            
            return not has_technical_jargon
            
        except:
            return False
    
    def _check_actionable_message(self, response) -> bool:
        """Check if error message provides actionable guidance"""
        try:
            messages = self._extract_error_messages(response)
            
            if not messages:
                return False
            
            # Actionable indicators
            actionable_patterns = [
                r'required',
                r'must be',
                r'should be',
                r'expected',
                r'provide',
                r'enter',
                r'check',
                r'verify'
            ]
            
            message_text = ' '.join(messages).lower()
            
            return any(re.search(pattern, message_text) for pattern in actionable_patterns)
            
        except:
            return False
    
    def analyze_api_documentation(self):
        """Analyze API documentation completeness and quality"""
        print("\n=== API Documentation Analysis ===")
        
        # Test documentation endpoints
        doc_endpoints = [
            {'url': '/swagger/', 'name': 'Swagger UI'},
            {'url': '/redoc/', 'name': 'ReDoc UI'},
            {'url': '/swagger.json', 'name': 'OpenAPI Schema'},
        ]
        
        doc_analysis = DocumentationAnalysis(
            swagger_available=False,
            redoc_available=False,
            endpoint_documented=False,
            parameters_documented=False,
            responses_documented=False,
            examples_provided=False,
            error_responses_documented=False,
            authentication_documented=False
        )
        
        for endpoint in doc_endpoints:
            try:
                response = self.django_client.get(endpoint['url'])
                
                if response.status_code == 200:
                    print(f"  ✓ {endpoint['name']} available")
                    
                    if 'swagger' in endpoint['url']:
                        doc_analysis.swagger_available = True
                    elif 'redoc' in endpoint['url']:
                        doc_analysis.redoc_available = True
                        
                else:
                    print(f"  ✗ {endpoint['name']} not available (status: {response.status_code})")
                    
            except Exception as e:
                print(f"  ✗ Error accessing {endpoint['name']}: {str(e)}")
        
        # Analyze OpenAPI schema if available
        try:
            schema_response = self.django_client.get('/swagger.json')
            if schema_response.status_code == 200:
                schema_data = schema_response.json()
                doc_analysis = self._analyze_openapi_schema(schema_data, doc_analysis)
        except Exception as e:
            print(f"  ✗ Could not analyze OpenAPI schema: {str(e)}")
        
        self.results['documentation_analysis'] = asdict(doc_analysis)
    
    def _analyze_openapi_schema(self, schema_data: Dict[str, Any], 
                               doc_analysis: DocumentationAnalysis) -> DocumentationAnalysis:
        """Analyze OpenAPI schema for documentation completeness"""
        
        paths = schema_data.get('paths', {})
        
        if paths:
            doc_analysis.endpoint_documented = True
            
            # Check for parameter documentation
            has_parameters = any(
                'parameters' in operation
                for path_data in paths.values()
                for operation in path_data.values()
                if isinstance(operation, dict)
            )
            doc_analysis.parameters_documented = has_parameters
            
            # Check for response documentation
            has_responses = any(
                'responses' in operation and len(operation['responses']) > 1
                for path_data in paths.values()
                for operation in path_data.values()
                if isinstance(operation, dict)
            )
            doc_analysis.responses_documented = has_responses
            
            # Check for examples
            has_examples = any(
                'examples' in str(operation) or 'example' in str(operation)
                for path_data in paths.values()
                for operation in path_data.values()
                if isinstance(operation, dict)
            )
            doc_analysis.examples_provided = has_examples
            
            # Check for error response documentation
            has_error_responses = any(
                any(status_code.startswith('4') or status_code.startswith('5') 
                    for status_code in operation.get('responses', {}).keys())
                for path_data in paths.values()
                for operation in path_data.values()
                if isinstance(operation, dict)
            )
            doc_analysis.error_responses_documented = has_error_responses
        
        # Check for authentication documentation
        security_schemes = schema_data.get('components', {}).get('securitySchemes', {})
        doc_analysis.authentication_documented = bool(security_schemes)
        
        return doc_analysis
    
    def _analyze_endpoint_consistency(self):
        """Analyze consistency across endpoints"""
        print("\n=== Endpoint Consistency Analysis ===")
        
        analyses = self.results['endpoint_analysis']
        
        # Check response format consistency
        response_formats = defaultdict(int)
        status_code_usage = defaultdict(int)
        content_types = defaultdict(int)
        
        for analysis in analyses:
            response_formats[analysis.response_type] += 1
            status_code_usage[analysis.status_code] += 1
            content_types[analysis.content_type] += 1
        
        # Identify inconsistencies
        if len(response_formats) > 2:  # Allow for Response and JsonResponse
            self.results['consistency_issues'].append({
                'type': 'Response Format Inconsistency',
                'details': f"Multiple response types found: {dict(response_formats)}",
                'severity': 'medium'
            })
        
        # Check error format consistency
        error_formats = set()
        for analysis in analyses:
            if analysis.status_code >= 400:
                error_formats.add(analysis.error_format_consistent)
        
        if len(error_formats) > 1:
            self.results['consistency_issues'].append({
                'type': 'Error Format Inconsistency',
                'details': "Inconsistent error formats across endpoints",
                'severity': 'high'
            })
        
        print(f"  Response formats: {dict(response_formats)}")
        print(f"  Content types: {dict(content_types)}")
        print(f"  Consistency issues found: {len(self.results['consistency_issues'])}")
    
    def generate_recommendations(self):
        """Generate recommendations based on analysis results"""
        print("\n=== Generating Recommendations ===")
        
        recommendations = []
        
        # Analyze endpoint analysis results
        endpoint_analyses = self.results['endpoint_analysis']
        
        # Check for missing error handling
        endpoints_without_error_handling = [
            a for a in endpoint_analyses if not a.has_error_handling
        ]
        
        if endpoints_without_error_handling:
            recommendations.append({
                'category': 'Error Handling',
                'priority': 'High',
                'issue': 'Missing error handling in some endpoints',
                'recommendation': 'Implement consistent error handling across all API endpoints',
                'affected_endpoints': [a.endpoint for a in endpoints_without_error_handling]
            })
        
        # Check for inconsistent error formats
        inconsistent_error_formats = [
            a for a in endpoint_analyses if not a.error_format_consistent and a.status_code >= 400
        ]
        
        if inconsistent_error_formats:
            recommendations.append({
                'category': 'Error Format Consistency',
                'priority': 'High',
                'issue': 'Inconsistent error response formats',
                'recommendation': 'Standardize error responses using StandardErrorResponse class',
                'affected_endpoints': [a.endpoint for a in inconsistent_error_formats]
            })
        
        # Check for non-standard status codes
        non_standard_status = [
            a for a in endpoint_analyses if not a.uses_standard_status_codes
        ]
        
        if non_standard_status:
            recommendations.append({
                'category': 'HTTP Status Codes',
                'priority': 'Medium',
                'issue': 'Non-standard HTTP status codes used',
                'recommendation': 'Use standard HTTP status codes for better API compliance',
                'affected_endpoints': [a.endpoint for a in non_standard_status]
            })
        
        # Check documentation completeness
        doc_analysis = self.results['documentation_analysis']
        
        if not doc_analysis.get('swagger_available', False):
            recommendations.append({
                'category': 'Documentation',
                'priority': 'Medium',
                'issue': 'Swagger UI not available',
                'recommendation': 'Ensure Swagger UI is accessible for API documentation'
            })
        
        if not doc_analysis.get('error_responses_documented', False):
            recommendations.append({
                'category': 'Documentation',
                'priority': 'Medium',
                'issue': 'Error responses not documented',
                'recommendation': 'Document all possible error responses in OpenAPI schema'
            })
        
        # Security recommendations
        endpoints_missing_security_headers = [
            a for a in endpoint_analyses if not a.security_headers
        ]
        
        if endpoints_missing_security_headers:
            recommendations.append({
                'category': 'Security',
                'priority': 'High',
                'issue': 'Missing security headers',
                'recommendation': 'Add security headers (X-Content-Type-Options, X-Frame-Options, etc.)',
                'affected_endpoints': [a.endpoint for a in endpoints_missing_security_headers]
            })
        
        # Performance recommendations
        slow_endpoints = [
            a for a in endpoint_analyses 
            if a.performance_metrics.get('response_time_ms', 0) > 1000
        ]
        
        if slow_endpoints:
            recommendations.append({
                'category': 'Performance',
                'priority': 'Medium',
                'issue': 'Slow response times detected',
                'recommendation': 'Optimize slow endpoints for better performance',
                'affected_endpoints': [a.endpoint for a in slow_endpoints]
            })
        
        self.results['recommendations'] = recommendations
        
        print(f"  Generated {len(recommendations)} recommendations")
        for rec in recommendations:
            print(f"    {rec['priority']}: {rec['issue']}")
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"api_design_error_handling_analysis_results_{timestamp}.json"
        
        # Add summary statistics
        self.results['summary'] = {
            'total_endpoints_analyzed': len(self.results['endpoint_analysis']),
            'endpoints_with_proper_error_handling': len([
                a for a in self.results['endpoint_analysis'] if a.has_error_handling
            ]),
            'endpoints_with_consistent_errors': len([
                a for a in self.results['endpoint_analysis'] if a.error_format_consistent
            ]),
            'total_error_scenarios_tested': len(self.results['error_handling_analysis']),
            'consistency_issues_found': len(self.results['consistency_issues']),
            'security_issues_found': len(self.results['security_issues']),
            'total_recommendations': len(self.results['recommendations']),
            'documentation_completeness_score': self._calculate_documentation_score(),
            'analysis_timestamp': timestamp
        }
        
        # Save detailed results
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n=== Analysis Complete ===")
        print(f"Report saved to: {report_file}")
        
        # Print summary
        summary = self.results['summary']
        print(f"\nSummary:")
        print(f"  Total endpoints analyzed: {summary['total_endpoints_analyzed']}")
        print(f"  Endpoints with proper error handling: {summary['endpoints_with_proper_error_handling']}")
        print(f"  Endpoints with consistent error format: {summary['endpoints_with_consistent_errors']}")
        print(f"  Error scenarios tested: {summary['total_error_scenarios_tested']}")
        print(f"  Consistency issues: {summary['consistency_issues_found']}")
        print(f"  Security issues: {summary['security_issues_found']}")
        print(f"  Recommendations generated: {summary['total_recommendations']}")
        print(f"  Documentation completeness: {summary['documentation_completeness_score']:.1%}")
        
        return report_file
    
    def _calculate_documentation_score(self) -> float:
        """Calculate documentation completeness score"""
        doc_analysis = self.results['documentation_analysis']
        
        criteria = [
            'swagger_available',
            'redoc_available', 
            'endpoint_documented',
            'parameters_documented',
            'responses_documented',
            'examples_provided',
            'error_responses_documented',
            'authentication_documented'
        ]
        
        score = sum(1 for criterion in criteria if doc_analysis.get(criterion, False))
        return score / len(criteria)
    
    def run_complete_analysis(self):
        """Run the complete API design and error handling analysis"""
        print("Starting API Design and Error Handling Analysis...")
        print("=" * 60)
        
        try:
            # Setup
            self.setup_test_data()
            self.authenticate_user()
            
            # Run analyses
            self.analyze_api_endpoints()
            self.analyze_error_handling_patterns()
            self.analyze_api_documentation()
            self.generate_recommendations()
            
            # Generate report
            report_file = self.generate_report()
            
            print(f"\n✓ Analysis completed successfully!")
            print(f"✓ Report saved to: {report_file}")
            
            return True
            
        except Exception as e:
            print(f"\n✗ Analysis failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main function to run the analysis"""
    analyzer = APIDesignErrorHandlingAnalyzer()
    success = analyzer.run_complete_analysis()
    
    if success:
        print("\n" + "=" * 60)
        print("API Design and Error Handling Analysis Summary")
        print("=" * 60)
        print("✓ API endpoint functionality tested")
        print("✓ Error handling consistency analyzed")
        print("✓ HTTP status code usage validated")
        print("✓ API documentation completeness assessed")
        print("✓ Security headers analyzed")
        print("✓ Performance metrics collected")
        print("✓ Recommendations generated")
        print("\nRequirements 5.3, 5.2, 6.2 analysis complete!")
    else:
        print("\n✗ Analysis failed. Check error messages above.")
        sys.exit(1)


if __name__ == "__main__":
    main()