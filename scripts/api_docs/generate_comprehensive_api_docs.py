#!/usr/bin/env python3
"""
Comprehensive API Documentation Generator for PRS Backend

This script generates complete OpenAPI documentation for all API endpoints,
including request/response schemas, examples, authentication requirements,
and interactive documentation.

Features:
- Auto-discover all API endpoints
- Generate swagger_auto_schema decorators for undocumented views
- Create comprehensive request/response schemas
- Add authentication documentation
- Generate usage examples
- Create integration guides

Usage:
    python generate_comprehensive_api_docs.py --analyze
    python generate_comprehensive_api_docs.py --generate-schemas
    python generate_comprehensive_api_docs.py --update-views
    python generate_comprehensive_api_docs.py --export-openapi
"""

import os
import sys
import json
import ast
import inspect
import importlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

# Add Django project to path
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent / "backend"
sys.path.insert(0, str(PROJECT_ROOT))

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core_config.settings")

try:
    import django
    django.setup()
    
    from django.urls import URLPattern, URLResolver, get_resolver
    from django.apps import apps
    from rest_framework.viewsets import ModelViewSet, ViewSet
    from rest_framework.views import APIView
    from rest_framework.generics import GenericAPIView
    from rest_framework import serializers
    from rest_framework.decorators import api_view
    from drf_yasg import openapi
    from drf_yasg.utils import swagger_auto_schema
    
    DJANGO_AVAILABLE = True
except Exception as e:
    print(f"Warning: Django setup failed: {e}")
    DJANGO_AVAILABLE = False


@dataclass
class APIEndpoint:
    """Represents an API endpoint with all its metadata"""
    path: str
    methods: List[str]
    view_class: str
    view_function: str
    module_path: str
    has_swagger_docs: bool
    permission_classes: List[str]
    authentication_classes: List[str]
    throttle_classes: List[str]
    serializer_class: Optional[str]
    filter_classes: List[str]
    description: str
    parameters: List[Dict[str, Any]]
    responses: Dict[int, str]
    tags: List[str]
    examples: Dict[str, Any]


@dataclass 
class APIModule:
    """Represents a Django app module with its API endpoints"""
    name: str
    endpoints: List[APIEndpoint]
    total_endpoints: int
    documented_endpoints: int
    coverage_percentage: float


class APIDocumentationGenerator:
    """Generates comprehensive API documentation for PRS backend"""
    
    def __init__(self):
        self.project_root = PROJECT_ROOT
        self.endpoints: List[APIEndpoint] = []
        self.modules: Dict[str, APIModule] = {}
        self.documentation_templates = {}
        
    def analyze_api_endpoints(self) -> Dict[str, Any]:
        """Analyze all API endpoints in the project"""
        print("🔍 Analyzing API endpoints...")
        
        if not DJANGO_AVAILABLE:
            print("❌ Django not available, using file-based analysis")
            return self._analyze_endpoints_from_files()
        
        try:
            resolver = get_resolver()
            self._discover_endpoints_recursive(resolver.url_patterns, '')
            
            # Group endpoints by module
            self._group_endpoints_by_module()
            
            # Calculate statistics
            stats = self._calculate_documentation_stats()
            
            print(f"✅ Found {len(self.endpoints)} endpoints across {len(self.modules)} modules")
            return stats
            
        except Exception as e:
            print(f"❌ Error analyzing endpoints: {e}")
            return self._analyze_endpoints_from_files()
    
    def _discover_endpoints_recursive(self, urlpatterns, prefix=''):
        """Recursively discover all URL patterns"""
        for pattern in urlpatterns:
            if isinstance(pattern, URLPattern):
                self._process_url_pattern(pattern, prefix)
            elif isinstance(pattern, URLResolver):
                self._discover_endpoints_recursive(
                    pattern.url_patterns, 
                    prefix + str(pattern.pattern)
                )
    
    def _process_url_pattern(self, pattern, prefix):
        """Process a single URL pattern and extract endpoint information"""
        try:
            full_path = prefix + str(pattern.pattern)
            callback = pattern.callback
            
            # Extract view information
            if hasattr(callback, 'view_class'):
                view_class = callback.view_class
                view_function = getattr(view_class, 'get', None) or getattr(view_class, 'post', None)
                module_path = view_class.__module__
                class_name = view_class.__name__
            elif hasattr(callback, 'cls'):
                view_class = callback.cls
                view_function = callback
                module_path = view_class.__module__
                class_name = view_class.__name__
            else:
                # Function-based view
                view_class = None
                view_function = callback
                module_path = callback.__module__
                class_name = callback.__name__
            
            # Determine HTTP methods
            methods = []
            if hasattr(view_class, 'http_method_names'):
                methods = view_class.http_method_names
            elif hasattr(view_function, 'methods'):
                methods = view_function.methods
            else:
                methods = ['GET']  # Default
            
            # Check for existing swagger documentation
            has_swagger_docs = self._has_swagger_documentation(view_class, view_function)
            
            # Extract other metadata
            permission_classes = self._get_permission_classes(view_class)
            authentication_classes = self._get_authentication_classes(view_class)
            throttle_classes = self._get_throttle_classes(view_class)
            serializer_class = self._get_serializer_class(view_class)
            
            # Create endpoint object
            endpoint = APIEndpoint(
                path=full_path,
                methods=[m.upper() for m in methods if m != 'options'],
                view_class=class_name,
                view_function=getattr(view_function, '__name__', str(view_function)),
                module_path=module_path,
                has_swagger_docs=has_swagger_docs,
                permission_classes=permission_classes,
                authentication_classes=authentication_classes,
                throttle_classes=throttle_classes,
                serializer_class=serializer_class,
                filter_classes=[],
                description=self._extract_description(view_class, view_function),
                parameters=[],
                responses={},
                tags=self._generate_tags(module_path),
                examples={}
            )
            
            self.endpoints.append(endpoint)
            
        except Exception as e:
            print(f"Warning: Could not process pattern {pattern}: {e}")
    
    def _analyze_endpoints_from_files(self) -> Dict[str, Any]:
        """Fallback method to analyze endpoints from Python files"""
        print("📁 Analyzing endpoints from source files...")
        
        # Find all Django app directories
        apps_dir = self.project_root / "apps"
        app_dirs = [d for d in apps_dir.iterdir() if d.is_dir() and (d / "views.py").exists()]
        
        for app_dir in app_dirs:
            app_name = app_dir.name
            self._analyze_app_views(app_name, app_dir)
        
        # Calculate stats
        return self._calculate_documentation_stats()
    
    def _analyze_app_views(self, app_name: str, app_dir: Path):
        """Analyze views in a Django app directory"""
        view_files = []
        
        # Find all view files
        view_files.append(app_dir / "views.py")
        for view_file in app_dir.glob("*_views.py"):
            view_files.append(view_file)
        
        app_endpoints = []
        
        for view_file in view_files:
            if view_file.exists():
                endpoints = self._parse_view_file(view_file, app_name)
                app_endpoints.extend(endpoints)
        
        if app_endpoints:
            documented_count = sum(1 for e in app_endpoints if e.has_swagger_docs)
            coverage = (documented_count / len(app_endpoints)) * 100 if app_endpoints else 0
            
            self.modules[app_name] = APIModule(
                name=app_name,
                endpoints=app_endpoints,
                total_endpoints=len(app_endpoints),
                documented_endpoints=documented_count,
                coverage_percentage=coverage
            )
            
            self.endpoints.extend(app_endpoints)
    
    def _parse_view_file(self, file_path: Path, app_name: str) -> List[APIEndpoint]:
        """Parse a Python view file to extract API endpoints"""
        endpoints = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST to find classes and functions
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    if self._is_api_view_class(node):
                        endpoint = self._extract_endpoint_from_class(node, file_path, app_name)
                        if endpoint:
                            endpoints.append(endpoint)
                
                elif isinstance(node, ast.FunctionDef):
                    if self._is_api_view_function(node):
                        endpoint = self._extract_endpoint_from_function(node, file_path, app_name)
                        if endpoint:
                            endpoints.append(endpoint)
        
        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")
        
        return endpoints
    
    def _is_api_view_class(self, node: ast.ClassDef) -> bool:
        """Check if a class is an API view"""
        # Check if it inherits from common API view base classes
        base_names = [base.id if hasattr(base, 'id') else str(base) for base in node.bases]
        api_base_classes = [
            'APIView', 'ModelViewSet', 'ViewSet', 'GenericAPIView',
            'ListAPIView', 'RetrieveAPIView', 'CreateAPIView',
            'UpdateAPIView', 'DestroyAPIView', 'ListCreateAPIView'
        ]
        
        return any(base in str(base_names) for base in api_base_classes)
    
    def _is_api_view_function(self, node: ast.FunctionDef) -> bool:
        """Check if a function is an API view"""
        # Check for @api_view decorator
        for decorator in node.decorator_list:
            if hasattr(decorator, 'id') and decorator.id == 'api_view':
                return True
            elif hasattr(decorator, 'attr') and decorator.attr == 'api_view':
                return True
        return False
    
    def _extract_endpoint_from_class(self, node: ast.ClassDef, file_path: Path, app_name: str) -> Optional[APIEndpoint]:
        """Extract endpoint information from a class node"""
        try:
            # Check for swagger_auto_schema decorators
            has_swagger_docs = self._has_swagger_decorator_in_class(node)
            
            # Extract docstring
            description = ast.get_docstring(node) or f"API endpoint for {node.name}"
            
            return APIEndpoint(
                path=f"/api/{app_name}/",  # Approximate path
                methods=self._extract_methods_from_class(node),
                view_class=node.name,
                view_function="",
                module_path=f"{app_name}.{file_path.stem}",
                has_swagger_docs=has_swagger_docs,
                permission_classes=self._extract_permission_classes_from_node(node),
                authentication_classes=[],
                throttle_classes=[],
                serializer_class=self._extract_serializer_class_from_node(node),
                filter_classes=[],
                description=description[:200] if description else "",
                parameters=[],
                responses={},
                tags=[app_name],
                examples={}
            )
        except Exception as e:
            print(f"Warning: Could not extract endpoint from class {node.name}: {e}")
            return None
    
    def _extract_endpoint_from_function(self, node: ast.FunctionDef, file_path: Path, app_name: str) -> Optional[APIEndpoint]:
        """Extract endpoint information from a function node"""
        try:
            # Check for swagger_auto_schema decorator
            has_swagger_docs = any(
                hasattr(d, 'id') and d.id == 'swagger_auto_schema' or
                hasattr(d, 'attr') and d.attr == 'swagger_auto_schema'
                for d in node.decorator_list
            )
            
            description = ast.get_docstring(node) or f"API endpoint: {node.name}"
            
            return APIEndpoint(
                path=f"/api/{app_name}/{node.name}/",
                methods=self._extract_methods_from_function(node),
                view_class="",
                view_function=node.name,
                module_path=f"{app_name}.{file_path.stem}",
                has_swagger_docs=has_swagger_docs,
                permission_classes=[],
                authentication_classes=[],
                throttle_classes=[],
                serializer_class=None,
                filter_classes=[],
                description=description[:200] if description else "",
                parameters=[],
                responses={},
                tags=[app_name],
                examples={}
            )
        except Exception as e:
            print(f"Warning: Could not extract endpoint from function {node.name}: {e}")
            return None
    
    def _has_swagger_decorator_in_class(self, node: ast.ClassDef) -> bool:
        """Check if a class has swagger_auto_schema decorators on its methods"""
        for child in node.body:
            if isinstance(child, ast.FunctionDef):
                for decorator in child.decorator_list:
                    if (hasattr(decorator, 'id') and decorator.id == 'swagger_auto_schema') or \
                       (hasattr(decorator, 'attr') and decorator.attr == 'swagger_auto_schema'):
                        return True
        return False
    
    def _extract_methods_from_class(self, node: ast.ClassDef) -> List[str]:
        """Extract HTTP methods from a ViewSet or APIView class"""
        methods = []
        for child in node.body:
            if isinstance(child, ast.FunctionDef):
                method_name = child.name.upper()
                if method_name in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
                    methods.append(method_name)
                elif child.name in ['list', 'create', 'retrieve', 'update', 'partial_update', 'destroy']:
                    # ViewSet methods
                    method_mapping = {
                        'list': 'GET', 'create': 'POST', 'retrieve': 'GET',
                        'update': 'PUT', 'partial_update': 'PATCH', 'destroy': 'DELETE'
                    }
                    methods.append(method_mapping[child.name])
        return list(set(methods)) or ['GET']
    
    def _extract_methods_from_function(self, node: ast.FunctionDef) -> List[str]:
        """Extract HTTP methods from @api_view decorator"""
        for decorator in node.decorator_list:
            if hasattr(decorator, 'id') and decorator.id == 'api_view':
                if decorator.args and len(decorator.args) > 0:
                    methods_arg = decorator.args[0]
                    if isinstance(methods_arg, ast.List):
                        return [elt.s for elt in methods_arg.elts if hasattr(elt, 's')]
        return ['GET']
    
    def _extract_permission_classes_from_node(self, node: ast.ClassDef) -> List[str]:
        """Extract permission classes from a class node"""
        permissions = []
        for child in node.body:
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if hasattr(target, 'id') and target.id == 'permission_classes':
                        if isinstance(child.value, ast.List):
                            permissions = [elt.id for elt in child.value.elts if hasattr(elt, 'id')]
        return permissions
    
    def _extract_serializer_class_from_node(self, node: ast.ClassDef) -> Optional[str]:
        """Extract serializer class from a class node"""
        for child in node.body:
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if hasattr(target, 'id') and target.id == 'serializer_class':
                        if hasattr(child.value, 'id'):
                            return child.value.id
        return None
    
    def _group_endpoints_by_module(self):
        """Group endpoints by their Django app module"""
        module_groups = {}
        
        for endpoint in self.endpoints:
            app_name = endpoint.module_path.split('.')[0]
            if app_name not in module_groups:
                module_groups[app_name] = []
            module_groups[app_name].append(endpoint)
        
        for app_name, endpoints in module_groups.items():
            documented_count = sum(1 for e in endpoints if e.has_swagger_docs)
            coverage = (documented_count / len(endpoints)) * 100 if endpoints else 0
            
            self.modules[app_name] = APIModule(
                name=app_name,
                endpoints=endpoints,
                total_endpoints=len(endpoints),
                documented_endpoints=documented_count,
                coverage_percentage=coverage
            )
    
    def _calculate_documentation_stats(self) -> Dict[str, Any]:
        """Calculate documentation coverage statistics"""
        total_endpoints = len(self.endpoints)
        documented_endpoints = sum(1 for e in self.endpoints if e.has_swagger_docs)
        coverage_percentage = (documented_endpoints / total_endpoints * 100) if total_endpoints > 0 else 0
        
        return {
            'total_endpoints': total_endpoints,
            'documented_endpoints': documented_endpoints,
            'undocumented_endpoints': total_endpoints - documented_endpoints,
            'coverage_percentage': coverage_percentage,
            'modules': {name: asdict(module) for name, module in self.modules.items()},
            'endpoints': [asdict(e) for e in self.endpoints]
        }
    
    def generate_swagger_schemas(self) -> Dict[str, str]:
        """Generate swagger_auto_schema decorators for undocumented endpoints"""
        print("📝 Generating swagger schemas for undocumented endpoints...")
        
        generated_schemas = {}
        
        for endpoint in self.endpoints:
            if not endpoint.has_swagger_docs:
                schema_code = self._generate_swagger_schema_for_endpoint(endpoint)
                file_key = f"{endpoint.module_path}.{endpoint.view_class or endpoint.view_function}"
                generated_schemas[file_key] = schema_code
        
        print(f"✅ Generated schemas for {len(generated_schemas)} endpoints")
        return generated_schemas
    
    def _generate_swagger_schema_for_endpoint(self, endpoint: APIEndpoint) -> str:
        """Generate swagger_auto_schema decorator code for an endpoint"""
        
        # Determine operation type
        primary_method = endpoint.methods[0] if endpoint.methods else 'GET'
        
        # Generate operation summary and description
        operation_summary = self._generate_operation_summary(endpoint)
        operation_description = endpoint.description or f"API endpoint for {endpoint.view_class or endpoint.view_function}"
        
        # Generate request body schema
        request_body = ""
        if primary_method in ['POST', 'PUT', 'PATCH']:
            if endpoint.serializer_class:
                request_body = f"request_body={endpoint.serializer_class},"
            else:
                request_body = "request_body=openapi.Schema(type=openapi.TYPE_OBJECT),"
        
        # Generate response schemas
        responses = self._generate_response_schemas(endpoint)
        
        # Generate tags
        tags = endpoint.tags or [endpoint.module_path.split('.')[0]]
        
        schema_template = f'''
@swagger_auto_schema(
    method='{primary_method.lower()}',
    operation_summary="{operation_summary}",
    operation_description="{operation_description}",
    {request_body}
    responses={{
{responses}
    }},
    tags={tags}
)'''
        
        return schema_template.strip()
    
    def _generate_operation_summary(self, endpoint: APIEndpoint) -> str:
        """Generate a concise operation summary"""
        if endpoint.view_function:
            action = endpoint.view_function.replace('_', ' ').title()
        elif endpoint.view_class:
            if 'ViewSet' in endpoint.view_class:
                method = endpoint.methods[0].lower() if endpoint.methods else 'get'
                action_map = {
                    'get': 'Retrieve', 'post': 'Create', 'put': 'Update',
                    'patch': 'Partial Update', 'delete': 'Delete'
                }
                action = action_map.get(method, method.title())
            else:
                action = endpoint.view_class.replace('View', '').replace('API', '')
        else:
            action = "API Operation"
        
        return f"{action} {endpoint.module_path.split('.')[0].title()}"
    
    def _generate_response_schemas(self, endpoint: APIEndpoint) -> str:
        """Generate response schema definitions"""
        responses = []
        
        # Success responses
        if 'GET' in endpoint.methods:
            if endpoint.serializer_class:
                responses.append(f"        200: {endpoint.serializer_class}(many=True)")
            else:
                responses.append("        200: openapi.Response(description='Success')")
        
        if 'POST' in endpoint.methods:
            if endpoint.serializer_class:
                responses.append(f"        201: {endpoint.serializer_class}")
            else:
                responses.append("        201: openapi.Response(description='Created')")
        
        if any(method in endpoint.methods for method in ['PUT', 'PATCH']):
            if endpoint.serializer_class:
                responses.append(f"        200: {endpoint.serializer_class}")
            else:
                responses.append("        200: openapi.Response(description='Updated')")
        
        if 'DELETE' in endpoint.methods:
            responses.append("        204: openapi.Response(description='Deleted')")
        
        # Error responses
        if endpoint.permission_classes:
            responses.append("        401: openapi.Response(description='Unauthorized')")
            responses.append("        403: openapi.Response(description='Forbidden')")
        
        responses.append("        400: openapi.Response(description='Bad Request')")
        responses.append("        500: openapi.Response(description='Internal Server Error')")
        
        return ',\n'.join(responses)
    
    def export_openapi_schema(self, output_path: str):
        """Export complete OpenAPI schema as JSON"""
        print("📤 Exporting OpenAPI schema...")
        
        # Build OpenAPI schema structure
        schema = {
            "openapi": "3.0.0",
            "info": {
                "title": "Payment Receiving System API",
                "version": "1.0.0",
                "description": "Comprehensive API documentation for the PRS Backend",
                "contact": {
                    "email": "contact@prs.local"
                },
                "license": {
                    "name": "BSD License"
                }
            },
            "servers": [
                {
                    "url": "http://localhost:8000/api",
                    "description": "Development server"
                },
                {
                    "url": "https://your-domain.com/api",
                    "description": "Production server"
                }
            ],
            "paths": {},
            "components": {
                "securitySchemes": {
                    "TokenAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "Authorization",
                        "description": "Token-based authentication (format: 'Token <your_token>')"
                    }
                }
            },
            "security": [
                {"TokenAuth": []}
            ],
            "tags": []
        }
        
        # Add endpoints to schema
        for endpoint in self.endpoints:
            self._add_endpoint_to_schema(schema, endpoint)
        
        # Add tags from modules
        for module_name, module in self.modules.items():
            schema["tags"].append({
                "name": module_name,
                "description": f"API endpoints for {module_name} module"
            })
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(schema, f, indent=2, ensure_ascii=False)
        
        print(f"✅ OpenAPI schema exported to {output_path}")
    
    def _add_endpoint_to_schema(self, schema: Dict[str, Any], endpoint: APIEndpoint):
        """Add a single endpoint to the OpenAPI schema"""
        path_key = endpoint.path
        if path_key not in schema["paths"]:
            schema["paths"][path_key] = {}
        
        for method in endpoint.methods:
            method_lower = method.lower()
            schema["paths"][path_key][method_lower] = {
                "summary": self._generate_operation_summary(endpoint),
                "description": endpoint.description or f"API endpoint for {endpoint.view_class or endpoint.view_function}",
                "tags": endpoint.tags or [endpoint.module_path.split('.')[0]],
                "responses": {
                    "200": {"description": "Success"},
                    "400": {"description": "Bad Request"},
                    "401": {"description": "Unauthorized"},
                    "500": {"description": "Internal Server Error"}
                }
            }
            
            if endpoint.permission_classes:
                schema["paths"][path_key][method_lower]["security"] = [{"TokenAuth": []}]
    
    def generate_integration_documentation(self) -> str:
        """Generate comprehensive integration documentation"""
        print("📚 Generating integration documentation...")
        
        doc_content = f'''# PRS API Integration Guide

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overview

This guide provides comprehensive information for integrating with the Payment Receiving System (PRS) API.

## Base URLs

- **Development**: `http://localhost:8000/api/`
- **Production**: `https://your-domain.com/api/`

## Authentication

The PRS API uses Token-based authentication. Include your token in the Authorization header:

```http
Authorization: Token <your-token-here>
```

### Getting Your Token

#### Regular Users
```http
POST /api/auth/login/
Content-Type: application/json

{{
  "email": "user@example.com",
  "password": "your-password"
}}
```

#### Admin Users (with OTP)
```http
# Step 1: Initiate login
POST /api/auth/login/super-admin/
Content-Type: application/json

{{
  "email": "admin@example.com", 
  "password": "your-password"
}}

# Step 2: Verify OTP
POST /api/auth/login/super-admin/verify/
Content-Type: application/json

{{
  "email": "admin@example.com",
  "otp": "123456"
}}
```

## API Modules

{self._generate_module_documentation()}

## Error Handling

The API returns standardized error responses:

```json
{{
  "error": {{
    "code": "VALIDATION_ERROR",
    "message": "Input validation failed",
    "details": {{
      "field": ["This field is required"]
    }},
    "correlation_id": "abc-123-def"
  }}
}}
```

### Common Error Codes

- `VALIDATION_ERROR` - Input validation failed
- `AUTHENTICATION_ERROR` - Authentication required
- `PERMISSION_DENIED` - Insufficient permissions
- `NOT_FOUND` - Resource not found
- `RATE_LIMIT_EXCEEDED` - Too many requests

## Rate Limiting

API endpoints are rate limited to prevent abuse:
- **Authenticated users**: 1000 requests/hour
- **Anonymous users**: 100 requests/hour
- **Login attempts**: 5 attempts/5 minutes

## Pagination

List endpoints support pagination:

```http
GET /api/deals/?page=2&page_size=50
```

Response format:
```json
{{
  "count": 150,
  "next": "http://api.example.com/deals/?page=3",
  "previous": "http://api.example.com/deals/?page=1",
  "results": [...]
}}
```

## SDKs and Examples

### Python Example
```python
import requests

# Authentication
response = requests.post('http://localhost:8000/api/auth/login/', {{
    'email': 'user@example.com',
    'password': 'password'
}})
token = response.json()['token']

# API Request
headers = {{'Authorization': f'Token {{token}}'}}
response = requests.get('http://localhost:8000/api/deals/', headers=headers)
deals = response.json()
```

### JavaScript Example
```javascript
// Authentication
const authResponse = await fetch('http://localhost:8000/api/auth/login/', {{
  method: 'POST',
  headers: {{'Content-Type': 'application/json'}},
  body: JSON.stringify({{
    email: 'user@example.com',
    password: 'password'
  }})
}});
const {{ token }} = await authResponse.json();

// API Request
const response = await fetch('http://localhost:8000/api/deals/', {{
  headers: {{'Authorization': `Token ${{token}}`}}
}});
const deals = await response.json();
```

## Testing

Use the interactive API documentation:
- **Swagger UI**: `http://localhost:8000/swagger/`
- **ReDoc**: `http://localhost:8000/redoc/`

## Support

For API support and questions:
- Email: contact@prs.local
- Documentation: Full API reference available in Swagger UI
'''

        return doc_content
    
    def _generate_module_documentation(self) -> str:
        """Generate documentation for each API module"""
        sections = []
        
        for module_name, module in self.modules.items():
            section = f'''
### {module_name.title()} Module

Documentation coverage: {module.coverage_percentage:.1f}% ({module.documented_endpoints}/{module.total_endpoints} endpoints)

**Key endpoints:**
'''
            # Add top endpoints for this module
            for endpoint in module.endpoints[:5]:  # Show first 5 endpoints
                methods_str = ', '.join(endpoint.methods)
                section += f"- `{methods_str} {endpoint.path}` - {endpoint.description[:100] if endpoint.description else 'API endpoint'}\n"
            
            if len(module.endpoints) > 5:
                section += f"- ... and {len(module.endpoints) - 5} more endpoints\n"
            
            sections.append(section)
        
        return '\n'.join(sections)
    
    def create_documentation_report(self, output_path: str):
        """Create a comprehensive documentation analysis report"""
        stats = self._calculate_documentation_stats()
        
        report = f'''# API Documentation Analysis Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

- **Total API Endpoints**: {stats['total_endpoints']}
- **Documented Endpoints**: {stats['documented_endpoints']}
- **Documentation Coverage**: {stats['coverage_percentage']:.1f}%
- **Modules Analyzed**: {len(self.modules)}

## Module Breakdown

| Module | Endpoints | Documented | Coverage | Status |
|--------|-----------|------------|----------|---------|
'''
        
        for module_name, module_data in stats['modules'].items():
            status = "✅ Good" if module_data['coverage_percentage'] >= 80 else \
                     "⚠️ Needs Improvement" if module_data['coverage_percentage'] >= 50 else \
                     "❌ Poor"
            
            report += f"| {module_name} | {module_data['total_endpoints']} | {module_data['documented_endpoints']} | {module_data['coverage_percentage']:.1f}% | {status} |\n"
        
        report += f'''

## Recommendations

### High Priority
'''
        
        # Add specific recommendations
        poor_modules = [name for name, data in stats['modules'].items() 
                       if data['coverage_percentage'] < 50]
        
        if poor_modules:
            report += f"- **Improve documentation** for modules with poor coverage: {', '.join(poor_modules)}\n"
        
        undocumented_count = stats['undocumented_endpoints']
        if undocumented_count > 0:
            report += f"- **Add swagger_auto_schema decorators** to {undocumented_count} undocumented endpoints\n"
        
        report += '''
### Medium Priority
- Add request/response examples to all endpoints
- Implement proper error response schemas
- Add authentication requirements documentation
- Create integration examples for different programming languages

### Low Priority  
- Add OpenAPI extensions for advanced features
- Create SDK auto-generation from OpenAPI schema
- Implement API versioning documentation

## Implementation Plan

1. **Phase 1**: Add basic swagger_auto_schema decorators to all endpoints
2. **Phase 2**: Enhance schemas with proper request/response models
3. **Phase 3**: Add comprehensive examples and integration guides
4. **Phase 4**: Create automated documentation testing

## Tools Used

- **drf-yasg**: OpenAPI schema generation
- **Django REST Framework**: API framework
- **Custom analyzer**: Endpoint discovery and analysis
'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"📋 Documentation report created: {output_path}")
    
    # Helper methods for Django integration
    def _has_swagger_documentation(self, view_class, view_function) -> bool:
        """Check if a view has swagger documentation"""
        if not view_class and not view_function:
            return False
        
        try:
            # Check class methods for swagger decorators
            if view_class:
                for method_name in ['get', 'post', 'put', 'patch', 'delete']:
                    method = getattr(view_class, method_name, None)
                    if method and hasattr(method, '_swagger_auto_schema'):
                        return True
            
            # Check function for swagger decorator
            if view_function and hasattr(view_function, '_swagger_auto_schema'):
                return True
            
            return False
        except Exception:
            return False
    
    def _get_permission_classes(self, view_class) -> List[str]:
        """Extract permission classes from view"""
        if not view_class:
            return []
        
        permission_classes = getattr(view_class, 'permission_classes', [])
        return [cls.__name__ for cls in permission_classes]
    
    def _get_authentication_classes(self, view_class) -> List[str]:
        """Extract authentication classes from view"""
        if not view_class:
            return []
        
        auth_classes = getattr(view_class, 'authentication_classes', [])
        return [cls.__name__ for cls in auth_classes]
    
    def _get_throttle_classes(self, view_class) -> List[str]:
        """Extract throttle classes from view"""
        if not view_class:
            return []
        
        throttle_classes = getattr(view_class, 'throttle_classes', [])
        return [cls.__name__ for cls in throttle_classes]
    
    def _get_serializer_class(self, view_class) -> Optional[str]:
        """Extract serializer class from view"""
        if not view_class:
            return None
        
        serializer_class = getattr(view_class, 'serializer_class', None)
        return serializer_class.__name__ if serializer_class else None
    
    def _extract_description(self, view_class, view_function) -> str:
        """Extract description from view docstring"""
        if view_class and view_class.__doc__:
            return view_class.__doc__.strip()
        elif view_function and view_function.__doc__:
            return view_function.__doc__.strip()
        return ""
    
    def _generate_tags(self, module_path: str) -> List[str]:
        """Generate tags for OpenAPI schema"""
        parts = module_path.split('.')
        if len(parts) > 1:
            return [parts[0]]  # Use app name as tag
        return ['api']


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate comprehensive API documentation")
    parser.add_argument("--analyze", action="store_true", help="Analyze current documentation coverage")
    parser.add_argument("--generate-schemas", action="store_true", help="Generate swagger schemas for undocumented endpoints")
    parser.add_argument("--export-openapi", help="Export OpenAPI schema to JSON file")
    parser.add_argument("--integration-docs", help="Generate integration documentation")
    parser.add_argument("--report", help="Generate documentation analysis report")
    parser.add_argument("--output-dir", default="docs/api", help="Output directory for generated files")
    
    args = parser.parse_args()
    
    generator = APIDocumentationGenerator()
    
    if args.analyze:
        stats = generator.analyze_api_endpoints()
        print(f"\n📊 DOCUMENTATION ANALYSIS RESULTS:")
        print(f"   Total Endpoints: {stats['total_endpoints']}")
        print(f"   Documented: {stats['documented_endpoints']}")
        print(f"   Coverage: {stats['coverage_percentage']:.1f}%")
        
        print(f"\n📋 MODULE BREAKDOWN:")
        for module_name, module_data in stats['modules'].items():
            print(f"   {module_name}: {module_data['coverage_percentage']:.1f}% " +
                  f"({module_data['documented_endpoints']}/{module_data['total_endpoints']})")
    
    if args.generate_schemas:
        stats = generator.analyze_api_endpoints()
        schemas = generator.generate_swagger_schemas()
        
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        schemas_file = output_dir / "generated_swagger_schemas.py"
        with open(schemas_file, 'w') as f:
            f.write("# Generated Swagger Schemas\n")
            f.write("# Add these decorators to your view methods\n\n")
            for endpoint_key, schema_code in schemas.items():
                f.write(f"# {endpoint_key}\n")
                f.write(schema_code)
                f.write("\n\n")
        
        print(f"📝 Generated schemas saved to: {schemas_file}")
    
    if args.export_openapi:
        generator.analyze_api_endpoints()
        output_path = args.export_openapi
        generator.export_openapi_schema(output_path)
    
    if args.integration_docs:
        generator.analyze_api_endpoints()
        integration_doc = generator.generate_integration_documentation()
        
        with open(args.integration_docs, 'w', encoding='utf-8') as f:
            f.write(integration_doc)
        
        print(f"📚 Integration documentation created: {args.integration_docs}")
    
    if args.report:
        generator.analyze_api_endpoints()
        generator.create_documentation_report(args.report)
    
    if not any([args.analyze, args.generate_schemas, args.export_openapi, 
                args.integration_docs, args.report]):
        # Default: run analysis
        stats = generator.analyze_api_endpoints()
        print(f"\n🎯 QUICK ANALYSIS:")
        print(f"   Documentation Coverage: {stats['coverage_percentage']:.1f}%")
        print(f"   Run with --help to see all options")


if __name__ == "__main__":
    main()
