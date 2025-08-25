"""
API Documentation Optimizer - Task 4.3.1

Fixes API documentation completeness by implementing proper OpenAPI schema generation
and comprehensive API endpoint documentation.
"""

import logging
import re
import inspect
from collections import defaultdict
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from django.urls import URLPattern, URLResolver
from django.urls.resolvers import get_resolver
from django.http import HttpRequest
from rest_framework import serializers, viewsets
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.schemas.openapi import AutoSchema
from django.apps import apps
from django.conf import settings
import json

logger = logging.getLogger(__name__)


class APIDocumentationAnalyzer:
    """
    API Documentation analysis and optimization system
    Task 4.3.1: Core documentation analysis functionality
    """
    
    def __init__(self):
        self.discovered_endpoints = {}
        self.documentation_issues = []
        self.schema_issues = []
        self.missing_docs = []
        
        # Documentation requirements
        self.required_fields = [
            'summary',
            'description',
            'parameters',
            'responses',
            'tags'
        ]
        
        # Common response status codes
        self.standard_responses = {
            200: "Success",
            201: "Created", 
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error"
        }
    
    def analyze_api_documentation(self) -> Dict[str, Any]:
        """
        Analyze API documentation completeness and issues
        Task 4.3.1: Documentation completeness analysis
        """
        
        logger.info("Starting API documentation analysis...")
        
        # Discover all API endpoints
        self._discover_api_endpoints()
        
        # Analyze documentation completeness
        self._analyze_documentation_completeness()
        
        # Analyze OpenAPI schema issues
        self._analyze_schema_issues()
        
        # Generate improvement recommendations
        recommendations = self._generate_documentation_recommendations()
        
        # Calculate completeness score
        completeness_score = self._calculate_completeness_score()
        
        analysis_result = {
            'total_endpoints': len(self.discovered_endpoints),
            'documented_endpoints': len([
                ep for ep in self.discovered_endpoints.values() 
                if ep.get('has_documentation', False)
            ]),
            'completeness_score': completeness_score,
            'documentation_issues': self.documentation_issues,
            'schema_issues': self.schema_issues,
            'missing_documentation': self.missing_docs,
            'recommendations': recommendations,
            'endpoint_summary': self._generate_endpoint_summary()
        }
        
        logger.info(f"Documentation analysis completed: {completeness_score:.1f}% complete")
        return analysis_result
    
    def _discover_api_endpoints(self):
        """Discover all API endpoints in the application"""
        
        resolver = get_resolver()
        
        def extract_endpoints(url_patterns, base_path=""):
            for pattern in url_patterns:
                if isinstance(pattern, URLResolver):
                    # Recurse into URL resolver
                    new_base = base_path + str(pattern.pattern).rstrip('$')
                    extract_endpoints(pattern.url_patterns, new_base)
                elif isinstance(pattern, URLPattern):
                    # Extract endpoint information
                    path = base_path + str(pattern.pattern).rstrip('$')
                    
                    # Clean up path
                    path = path.replace('^', '').replace('$', '')
                    
                    # Get view function/class
                    callback = pattern.callback
                    view_class = None
                    view_function = None
                    
                    if hasattr(callback, 'view_class'):
                        view_class = callback.view_class
                    elif hasattr(callback, 'cls'):
                        view_class = callback.cls
                    else:
                        view_function = callback
                    
                    # Check if it's an API endpoint
                    if self._is_api_endpoint(path, view_class, view_function):
                        endpoint_info = self._analyze_endpoint(
                            path, view_class, view_function, pattern
                        )
                        
                        endpoint_key = f"{path}_{endpoint_info.get('methods', ['GET'])[0]}"
                        self.discovered_endpoints[endpoint_key] = endpoint_info
        
        try:
            extract_endpoints(resolver.url_patterns)
        except Exception as e:
            logger.error(f"Error discovering API endpoints: {e}")
    
    def _is_api_endpoint(self, path: str, view_class, view_function) -> bool:
        """Check if an endpoint is an API endpoint"""
        
        # Check path patterns that indicate API endpoints
        api_path_patterns = [
            '/api/',
            '/rest/',
            '/v1/',
            '/v2/',
            '/graphql/',
            'api.', 
            'rest.'
        ]
        
        if any(pattern in path.lower() for pattern in api_path_patterns):
            return True
        
        # Check if view is DRF-based
        if view_class:
            if issubclass(view_class, (APIView, viewsets.ViewSet)):
                return True
            
            # Check for DRF serializer usage
            if hasattr(view_class, 'serializer_class'):
                return True
        
        # Check if view function has API decorators
        if view_function and hasattr(view_function, '__wrapped__'):
            # Check for @api_view decorator
            if hasattr(view_function, 'cls') and issubclass(view_function.cls, APIView):
                return True
        
        return False
    
    def _analyze_endpoint(self, path: str, view_class, view_function, pattern) -> Dict[str, Any]:
        """Analyze a single API endpoint"""
        
        endpoint_info = {
            'path': path,
            'view_class': view_class.__name__ if view_class else None,
            'view_function': view_function.__name__ if view_function else None,
            'methods': [],
            'has_documentation': False,
            'has_serializer': False,
            'has_permissions': False,
            'docstring': None,
            'parameters': [],
            'responses': {},
            'issues': []
        }
        
        # Get allowed HTTP methods
        if view_class:
            if hasattr(view_class, 'http_method_names'):
                endpoint_info['methods'] = view_class.http_method_names
            elif hasattr(view_class, 'allowed_methods'):
                endpoint_info['methods'] = view_class.allowed_methods
            else:
                # Default DRF methods
                endpoint_info['methods'] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
        else:
            # For function-based views
            endpoint_info['methods'] = ['GET']  # Default
        
        # Check for documentation
        docstring = None
        if view_class:
            docstring = inspect.getdoc(view_class)
            
            # Check for serializer
            if hasattr(view_class, 'serializer_class'):
                endpoint_info['has_serializer'] = True
            
            # Check for permissions
            if hasattr(view_class, 'permission_classes'):
                endpoint_info['has_permissions'] = True
        elif view_function:
            docstring = inspect.getdoc(view_function)
        
        if docstring:
            endpoint_info['docstring'] = docstring
            endpoint_info['has_documentation'] = True
        
        # Analyze path parameters
        path_params = re.findall(r'<(\w+):(\w+)>', path)
        for param_type, param_name in path_params:
            endpoint_info['parameters'].append({
                'name': param_name,
                'type': param_type,
                'location': 'path',
                'required': True
            })
        
        # Check for common documentation issues
        self._check_endpoint_issues(endpoint_info)
        
        return endpoint_info
    
    def _check_endpoint_issues(self, endpoint_info: Dict[str, Any]):
        """Check for documentation issues in an endpoint"""
        
        issues = []
        
        # Missing documentation
        if not endpoint_info['has_documentation']:
            issues.append("Missing docstring/documentation")
        
        # Missing serializer for data endpoints
        if not endpoint_info['has_serializer']:
            if any(method in endpoint_info['methods'] for method in ['POST', 'PUT', 'PATCH']):
                issues.append("Missing serializer for data operations")
        
        # Missing permissions
        if not endpoint_info['has_permissions']:
            issues.append("No explicit permission classes defined")
        
        # Inadequate docstring
        if endpoint_info['docstring']:
            docstring = endpoint_info['docstring']
            if len(docstring) < 20:
                issues.append("Docstring too brief")
            
            # Check for key documentation elements
            if 'param' not in docstring.lower() and endpoint_info['parameters']:
                issues.append("Missing parameter documentation")
            
            if 'return' not in docstring.lower() and 'response' not in docstring.lower():
                issues.append("Missing response documentation")
        
        endpoint_info['issues'] = issues
    
    def _analyze_documentation_completeness(self):
        """Analyze overall documentation completeness"""
        
        for endpoint_key, endpoint in self.discovered_endpoints.items():
            # Check for missing essential documentation
            if not endpoint['has_documentation']:
                self.missing_docs.append({
                    'endpoint': endpoint['path'],
                    'methods': endpoint['methods'],
                    'issue': 'No documentation'
                })
            
            # Check for incomplete documentation
            if endpoint['issues']:
                self.documentation_issues.append({
                    'endpoint': endpoint['path'],
                    'methods': endpoint['methods'],
                    'issues': endpoint['issues']
                })
    
    def _analyze_schema_issues(self):
        """Analyze OpenAPI schema generation issues"""
        
        try:
            # Try to generate OpenAPI schema
            from rest_framework.schemas.openapi import get_openapi_info
            from django.urls import get_resolver
            
            # Common schema issues
            for endpoint_key, endpoint in self.discovered_endpoints.items():
                schema_issues = []
                
                # Missing response schemas
                if not endpoint.get('responses'):
                    schema_issues.append("Missing response schema definitions")
                
                # Missing request schemas
                if not endpoint['has_serializer'] and any(
                    method in endpoint['methods'] for method in ['POST', 'PUT', 'PATCH']
                ):
                    schema_issues.append("Missing request schema for data operations")
                
                # Missing parameter schemas
                if endpoint['parameters'] and not all(
                    param.get('schema') for param in endpoint['parameters']
                ):
                    schema_issues.append("Missing parameter schema definitions")
                
                if schema_issues:
                    self.schema_issues.append({
                        'endpoint': endpoint['path'],
                        'issues': schema_issues
                    })
                    
        except Exception as e:
            logger.warning(f"Could not analyze OpenAPI schema: {e}")
            self.schema_issues.append({
                'general': 'OpenAPI schema generation issues detected'
            })
    
    def _calculate_completeness_score(self) -> float:
        """Calculate documentation completeness score (0-100)"""
        
        if not self.discovered_endpoints:
            return 0.0
        
        total_endpoints = len(self.discovered_endpoints)
        documented_endpoints = len([
            ep for ep in self.discovered_endpoints.values() 
            if ep.get('has_documentation', False)
        ])
        
        # Base score from documented endpoints
        base_score = (documented_endpoints / total_endpoints) * 100
        
        # Penalties for issues
        total_issues = len(self.documentation_issues) + len(self.schema_issues)
        issue_penalty = min(total_issues * 2, 30)  # Max 30% penalty
        
        # Bonus for comprehensive documentation
        comprehensive_endpoints = len([
            ep for ep in self.discovered_endpoints.values()
            if ep.get('has_documentation', False) and 
               ep.get('has_serializer', False) and
               ep.get('has_permissions', False) and
               len(ep.get('issues', [])) == 0
        ])
        
        if comprehensive_endpoints > 0:
            bonus = (comprehensive_endpoints / total_endpoints) * 10  # Max 10% bonus
        else:
            bonus = 0
        
        final_score = max(0, base_score - issue_penalty + bonus)
        return min(100, final_score)
    
    def _generate_documentation_recommendations(self) -> List[Dict[str, Any]]:
        """Generate recommendations for improving API documentation"""
        
        recommendations = []
        
        # High-level recommendations
        completeness_score = self._calculate_completeness_score()
        
        if completeness_score < 50:
            recommendations.append({
                'priority': 'critical',
                'category': 'overall',
                'title': 'Critical Documentation Deficiency',
                'description': 'Less than 50% of API endpoints have documentation',
                'action': 'Prioritize adding basic documentation to all API endpoints'
            })
        elif completeness_score < 80:
            recommendations.append({
                'priority': 'high',
                'category': 'overall',
                'title': 'Documentation Gaps',
                'description': 'Significant documentation gaps exist',
                'action': 'Focus on completing documentation for core API endpoints'
            })
        
        # Specific endpoint recommendations
        undocumented_count = len([
            ep for ep in self.discovered_endpoints.values()
            if not ep.get('has_documentation', False)
        ])
        
        if undocumented_count > 0:
            recommendations.append({
                'priority': 'high',
                'category': 'endpoints',
                'title': f'{undocumented_count} Undocumented Endpoints',
                'description': 'Multiple API endpoints lack basic documentation',
                'action': 'Add docstrings and OpenAPI schema to undocumented endpoints'
            })
        
        # Schema recommendations
        if self.schema_issues:
            recommendations.append({
                'priority': 'medium',
                'category': 'schema',
                'title': 'OpenAPI Schema Issues',
                'description': 'OpenAPI schema generation has issues',
                'action': 'Fix schema generation and add proper serializers'
            })
        
        # Serializer recommendations
        missing_serializer_count = len([
            ep for ep in self.discovered_endpoints.values()
            if not ep.get('has_serializer', False) and any(
                method in ep['methods'] for method in ['POST', 'PUT', 'PATCH']
            )
        ])
        
        if missing_serializer_count > 0:
            recommendations.append({
                'priority': 'medium',
                'category': 'serializers',
                'title': f'{missing_serializer_count} Endpoints Missing Serializers',
                'description': 'Data manipulation endpoints lack proper serializers',
                'action': 'Add serializer classes for request/response validation and documentation'
            })
        
        # Permission recommendations
        missing_permissions_count = len([
            ep for ep in self.discovered_endpoints.values()
            if not ep.get('has_permissions', False)
        ])
        
        if missing_permissions_count > 0:
            recommendations.append({
                'priority': 'low',
                'category': 'permissions',
                'title': f'{missing_permissions_count} Endpoints Without Explicit Permissions',
                'description': 'Many endpoints lack explicit permission classes',
                'action': 'Add explicit permission classes for better security documentation'
            })
        
        return recommendations
    
    def _generate_endpoint_summary(self) -> Dict[str, Any]:
        """Generate summary statistics of API endpoints"""
        
        summary = {
            'total_endpoints': len(self.discovered_endpoints),
            'by_method': defaultdict(int),
            'by_documentation_status': {
                'documented': 0,
                'undocumented': 0,
                'partially_documented': 0
            },
            'by_issues': defaultdict(int),
            'top_paths': []
        }
        
        for endpoint in self.discovered_endpoints.values():
            # Count by method
            for method in endpoint['methods']:
                summary['by_method'][method] += 1
            
            # Count by documentation status
            if endpoint['has_documentation']:
                if endpoint['issues']:
                    summary['by_documentation_status']['partially_documented'] += 1
                else:
                    summary['by_documentation_status']['documented'] += 1
            else:
                summary['by_documentation_status']['undocumented'] += 1
            
            # Count by issue types
            for issue in endpoint['issues']:
                summary['by_issues'][issue] += 1
        
        # Get top-level paths
        paths = [endpoint['path'] for endpoint in self.discovered_endpoints.values()]
        path_prefixes = defaultdict(int)
        
        for path in paths:
            # Extract first path segment
            parts = path.strip('/').split('/')
            if parts and parts[0]:
                path_prefixes[f"/{parts[0]}/"] += 1
        
        summary['top_paths'] = sorted(
            path_prefixes.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return summary
    
    def generate_documentation_fixes(self) -> Dict[str, Any]:
        """
        Generate specific documentation fixes and improvements
        Task 4.3.1: Documentation fix generation
        """
        
        fixes = {
            'missing_docstrings': [],
            'missing_serializers': [],
            'schema_improvements': [],
            'permission_additions': []
        }
        
        for endpoint in self.discovered_endpoints.values():
            endpoint_path = endpoint['path']
            view_class = endpoint['view_class']
            
            # Generate docstring fixes
            if not endpoint['has_documentation']:
                docstring_template = self._generate_docstring_template(endpoint)
                fixes['missing_docstrings'].append({
                    'endpoint': endpoint_path,
                    'view_class': view_class,
                    'template': docstring_template
                })
            
            # Generate serializer fixes
            if not endpoint['has_serializer'] and any(
                method in endpoint['methods'] for method in ['POST', 'PUT', 'PATCH']
            ):
                serializer_template = self._generate_serializer_template(endpoint)
                fixes['missing_serializers'].append({
                    'endpoint': endpoint_path,
                    'view_class': view_class,
                    'template': serializer_template
                })
            
            # Generate schema improvements
            if 'Missing response schema definitions' in [
                issue for issues in self.schema_issues 
                for issue in issues.get('issues', [])
            ]:
                schema_template = self._generate_schema_template(endpoint)
                fixes['schema_improvements'].append({
                    'endpoint': endpoint_path,
                    'view_class': view_class,
                    'template': schema_template
                })
            
            # Generate permission additions
            if not endpoint['has_permissions']:
                permission_template = self._generate_permission_template(endpoint)
                fixes['permission_additions'].append({
                    'endpoint': endpoint_path,
                    'view_class': view_class,
                    'template': permission_template
                })
        
        return fixes
    
    def _generate_docstring_template(self, endpoint: Dict[str, Any]) -> str:
        """Generate docstring template for an endpoint"""
        
        methods = ", ".join(endpoint['methods'][:3])  # Show first 3 methods
        
        template = f'''"""
{endpoint['view_class'] or 'API Endpoint'} - {endpoint['path']}

{self._generate_description_from_path(endpoint['path'])}

**Supported HTTP Methods:** {methods}
"""'''
        
        # Add parameter documentation
        if endpoint['parameters']:
            template += "\n\n**Parameters:**\n"
            for param in endpoint['parameters']:
                template += f"- {param['name']} ({param['type']}): Description needed\n"
        
        # Add response documentation
        template += "\n\n**Responses:**\n"
        for status_code, description in self.standard_responses.items():
            if status_code in [200, 201, 400, 404, 500]:  # Common ones
                template += f"- {status_code}: {description}\n"
        
        return template
    
    def _generate_serializer_template(self, endpoint: Dict[str, Any]) -> str:
        """Generate serializer template for an endpoint"""
        
        class_name = f"{endpoint['view_class'] or 'Api'}Serializer"
        
        template = f'''
from rest_framework import serializers

class {class_name}(serializers.Serializer):
    """
    Serializer for {endpoint['path']} endpoint
    """
    
    # Add fields based on your model/data structure
    # Example fields:
    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(max_length=200)
    created_at = serializers.DateTimeField(read_only=True)
    
    def validate(self, data):
        """
        Add custom validation logic here
        """
        return data
'''
        
        return template
    
    def _generate_schema_template(self, endpoint: Dict[str, Any]) -> str:
        """Generate OpenAPI schema template for an endpoint"""
        
        template = f'''
# Add to your view class:
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class {endpoint['view_class'] or 'YourView'}:
    @swagger_auto_schema(
        operation_summary="{self._generate_description_from_path(endpoint['path'])}",
        operation_description="Detailed description of what this endpoint does.",
        responses={{
            200: openapi.Response(
                description="Success response",
                # Add schema here
            ),
            400: openapi.Response(description="Bad request"),
            404: openapi.Response(description="Not found"),
        }}
    )
    def get(self, request):
        # Your view logic here
        pass
'''
        
        return template
    
    def _generate_permission_template(self, endpoint: Dict[str, Any]) -> str:
        """Generate permission template for an endpoint"""
        
        template = f'''
# Add to your view class:
from rest_framework.permissions import IsAuthenticated, IsAdminUser

class {endpoint['view_class'] or 'YourView'}:
    permission_classes = [IsAuthenticated]  # Adjust as needed
    
    # Alternative permission options:
    # permission_classes = [IsAdminUser]  # Admin only
    # permission_classes = [AllowAny]     # Public access
    # permission_classes = [IsAuthenticatedOrReadOnly]  # Read public, write auth
'''
        
        return template
    
    def _generate_description_from_path(self, path: str) -> str:
        """Generate a description from the API path"""
        
        # Simple path-to-description conversion
        path_clean = path.strip('/')
        
        if 'api' in path_clean:
            path_clean = path_clean.replace('api/', '').replace('api', '')
        
        # Convert path segments to readable description
        parts = path_clean.split('/')
        if parts:
            resource = parts[0].replace('-', ' ').replace('_', ' ').title()
            return f"API endpoint for {resource} operations"
        
        return "API endpoint description needed"


# Global API documentation analyzer instance
api_documentation_analyzer = APIDocumentationAnalyzer()


# Utility functions
def analyze_api_documentation() -> Dict[str, Any]:
    """Convenience function to analyze API documentation"""
    return api_documentation_analyzer.analyze_api_documentation()


def generate_documentation_fixes() -> Dict[str, Any]:
    """Generate documentation fixes"""
    return api_documentation_analyzer.generate_documentation_fixes()


def get_documentation_completeness_score() -> float:
    """Get documentation completeness score"""
    analyzer = APIDocumentationAnalyzer()
    analyzer._discover_api_endpoints()
    analyzer._analyze_documentation_completeness()
    return analyzer._calculate_completeness_score()
