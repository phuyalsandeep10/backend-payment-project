"""
Enhanced Swagger/OpenAPI Configuration for PRS Backend

This module provides comprehensive OpenAPI schema configuration with:
- Custom schema classes
- Enhanced serializer documentation
- Authentication documentation
- Error response schemas
- Example data generation
"""

from drf_yasg import openapi
from drf_yasg.inspectors import SwaggerAutoSchema, FieldInspector, PaginatorInspector
from drf_yasg.utils import swagger_auto_schema
from rest_framework import serializers, status
from rest_framework.response import Response
from typing import Dict, Any, List, Optional
import json
from decimal import Decimal
from datetime import datetime
from django.conf import settings


# ===================== CUSTOM SCHEMA CLASSES =====================

class EnhancedAutoSchema(SwaggerAutoSchema):
    """Enhanced auto schema with improved documentation generation"""
    
    def get_operation_id(self, operation_keys):
        """Generate more descriptive operation IDs"""
        operation_id = super().get_operation_id(operation_keys)
        # Add module prefix for better organization
        if len(operation_keys) >= 3:
            module = operation_keys[0]
            action = operation_keys[-1]
            return f"{module}_{action}"
        return operation_id
    
    def get_security_definition(self):
        """Enhanced security definitions"""
        return [
            {
                'Token Authentication': []
            }
        ]
    
    def get_produces(self):
        """Define supported response content types"""
        return ['application/json']
    
    def get_consumes(self):
        """Define supported request content types"""
        return ['application/json', 'multipart/form-data', 'application/x-www-form-urlencoded']


class EnhancedFieldInspector(FieldInspector):
    """Enhanced field inspector for better serializer documentation"""
    
    def field_to_swagger_object(self, field, swagger_object_type, use_references, **kwargs):
        """Convert serializer fields to swagger objects with enhanced documentation"""
        swagger_object = super().field_to_swagger_object(
            field, swagger_object_type, use_references, **kwargs
        )
        
        # Add examples for common field types
        if hasattr(field, 'help_text') and field.help_text:
            swagger_object.description = field.help_text
        
        # Add examples based on field type
        if isinstance(field, serializers.EmailField):
            swagger_object.example = "user@example.com"
        elif isinstance(field, serializers.URLField):
            swagger_object.example = "https://example.com"
        elif isinstance(field, serializers.DecimalField):
            swagger_object.example = "99.99"
        elif isinstance(field, serializers.DateTimeField):
            swagger_object.example = "2024-01-15T10:30:00Z"
        elif isinstance(field, serializers.DateField):
            swagger_object.example = "2024-01-15"
        elif isinstance(field, serializers.BooleanField):
            swagger_object.example = True
        
        return swagger_object


# ===================== COMMON RESPONSE SCHEMAS =====================

# Success response schemas
success_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN, example=True),
        'data': openapi.Schema(type=openapi.TYPE_OBJECT),
        'message': openapi.Schema(type=openapi.TYPE_STRING, example="Operation completed successfully")
    }
)

# Error response schemas
error_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'error': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'code': openapi.Schema(type=openapi.TYPE_STRING, example="VALIDATION_ERROR"),
                'message': openapi.Schema(type=openapi.TYPE_STRING, example="Input validation failed"),
                'details': openapi.Schema(type=openapi.TYPE_OBJECT),
                'correlation_id': openapi.Schema(type=openapi.TYPE_STRING, example="abc-123-def")
            }
        )
    }
)

# Authentication error schema
auth_error_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'detail': openapi.Schema(type=openapi.TYPE_STRING, example="Authentication credentials were not provided.")
    }
)

# Permission denied schema
permission_error_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'detail': openapi.Schema(type=openapi.TYPE_STRING, example="You do not have permission to perform this action.")
    }
)

# Validation error schema
validation_error_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'field_name': openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(type=openapi.TYPE_STRING),
            example=["This field is required."]
        )
    }
)

# Pagination schema
pagination_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'count': openapi.Schema(type=openapi.TYPE_INTEGER, example=150),
        'next': openapi.Schema(type=openapi.TYPE_STRING, example="http://api.example.com/endpoint/?page=3"),
        'previous': openapi.Schema(type=openapi.TYPE_STRING, example="http://api.example.com/endpoint/?page=1"),
        'results': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT))
    }
)


# ===================== AUTHENTICATION SCHEMAS =====================

login_request_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['email', 'password'],
    properties={
        'email': openapi.Schema(type=openapi.TYPE_STRING, example="user@example.com"),
        'password': openapi.Schema(type=openapi.TYPE_STRING, example="securepassword123")
    }
)

login_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'token': openapi.Schema(type=openapi.TYPE_STRING, example="9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"),
        'user': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                'email': openapi.Schema(type=openapi.TYPE_STRING, example="user@example.com"),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING, example="John"),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING, example="Doe"),
                'role': openapi.Schema(type=openapi.TYPE_STRING, example="sales_person")
            }
        )
    }
)

otp_request_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['email', 'otp'],
    properties={
        'email': openapi.Schema(type=openapi.TYPE_STRING, example="admin@example.com"),
        'otp': openapi.Schema(type=openapi.TYPE_STRING, example="123456")
    }
)


# ===================== COMMON PARAMETERS =====================

# Common query parameters
page_parameter = openapi.Parameter(
    'page', openapi.IN_QUERY,
    description="Page number for pagination",
    type=openapi.TYPE_INTEGER,
    default=1
)

page_size_parameter = openapi.Parameter(
    'page_size', openapi.IN_QUERY, 
    description="Number of items per page",
    type=openapi.TYPE_INTEGER,
    default=20
)

search_parameter = openapi.Parameter(
    'search', openapi.IN_QUERY,
    description="Search term for filtering results", 
    type=openapi.TYPE_STRING
)

ordering_parameter = openapi.Parameter(
    'ordering', openapi.IN_QUERY,
    description="Field to order results by (prefix with '-' for descending)",
    type=openapi.TYPE_STRING
)

# Authentication header
auth_header_parameter = openapi.Parameter(
    'Authorization', openapi.IN_HEADER,
    description="Token authentication header (format: 'Token <your_token>')",
    type=openapi.TYPE_STRING,
    required=True
)


# ===================== RESPONSE HELPERS =====================

class StandardAPIResponses:
    """Standard API response definitions"""
    
    @staticmethod
    def success_200(description="Success", schema=None):
        return openapi.Response(description=description, schema=schema)
    
    @staticmethod
    def created_201(description="Created", schema=None):
        return openapi.Response(description=description, schema=schema)
    
    @staticmethod
    def no_content_204(description="No content"):
        return openapi.Response(description=description)
    
    @staticmethod
    def bad_request_400(description="Bad request"):
        return openapi.Response(description=description, schema=validation_error_schema)
    
    @staticmethod
    def unauthorized_401(description="Unauthorized"):
        return openapi.Response(description=description, schema=auth_error_schema)
    
    @staticmethod
    def forbidden_403(description="Forbidden"):
        return openapi.Response(description=description, schema=permission_error_schema)
    
    @staticmethod
    def not_found_404(description="Not found"):
        return openapi.Response(description=description, schema=error_response_schema)
    
    @staticmethod
    def server_error_500(description="Internal server error"):
        return openapi.Response(description=description, schema=error_response_schema)
    
    @staticmethod
    def standard_responses(include_auth=True, include_pagination=False):
        """Get standard response set"""
        responses = {
            400: StandardAPIResponses.bad_request_400(),
            500: StandardAPIResponses.server_error_500()
        }
        
        if include_auth:
            responses.update({
                401: StandardAPIResponses.unauthorized_401(),
                403: StandardAPIResponses.forbidden_403()
            })
        
        return responses


# ===================== ENHANCED DECORATORS =====================

def enhanced_swagger_auto_schema(**kwargs):
    """Enhanced swagger_auto_schema with common defaults"""
    
    # Set default responses if not provided
    if 'responses' not in kwargs:
        kwargs['responses'] = StandardAPIResponses.standard_responses()
    
    # Add common parameters
    manual_parameters = kwargs.get('manual_parameters', [])
    if not any(p.name == 'Authorization' for p in manual_parameters):
        manual_parameters.append(auth_header_parameter)
    kwargs['manual_parameters'] = manual_parameters
    
    return swagger_auto_schema(**kwargs)


def document_viewset_actions(tags=None, **common_kwargs):
    """Decorator to document all ViewSet actions"""
    def decorator(viewset_class):
        action_docs = {
            'list': {
                'operation_summary': f'List {viewset_class.__name__.replace("ViewSet", "")} objects',
                'operation_description': f'Retrieve a list of {viewset_class.__name__.replace("ViewSet", "").lower()} objects with optional filtering and pagination.',
                'responses': {
                    200: openapi.Response(
                        description="List of objects",
                        schema=pagination_schema
                    ),
                    **StandardAPIResponses.standard_responses()
                }
            },
            'retrieve': {
                'operation_summary': f'Retrieve {viewset_class.__name__.replace("ViewSet", "")} object',
                'operation_description': f'Retrieve a specific {viewset_class.__name__.replace("ViewSet", "").lower()} object by ID.',
                'responses': {
                    200: StandardAPIResponses.success_200("Object details"),
                    404: StandardAPIResponses.not_found_404(),
                    **StandardAPIResponses.standard_responses()
                }
            },
            'create': {
                'operation_summary': f'Create {viewset_class.__name__.replace("ViewSet", "")} object',
                'operation_description': f'Create a new {viewset_class.__name__.replace("ViewSet", "").lower()} object.',
                'responses': {
                    201: StandardAPIResponses.created_201("Object created"),
                    **StandardAPIResponses.standard_responses()
                }
            },
            'update': {
                'operation_summary': f'Update {viewset_class.__name__.replace("ViewSet", "")} object',
                'operation_description': f'Update an existing {viewset_class.__name__.replace("ViewSet", "").lower()} object.',
                'responses': {
                    200: StandardAPIResponses.success_200("Object updated"),
                    404: StandardAPIResponses.not_found_404(),
                    **StandardAPIResponses.standard_responses()
                }
            },
            'partial_update': {
                'operation_summary': f'Partially update {viewset_class.__name__.replace("ViewSet", "")} object',
                'operation_description': f'Partially update an existing {viewset_class.__name__.replace("ViewSet", "").lower()} object.',
                'responses': {
                    200: StandardAPIResponses.success_200("Object updated"),
                    404: StandardAPIResponses.not_found_404(),
                    **StandardAPIResponses.standard_responses()
                }
            },
            'destroy': {
                'operation_summary': f'Delete {viewset_class.__name__.replace("ViewSet", "")} object',
                'operation_description': f'Delete an existing {viewset_class.__name__.replace("ViewSet", "").lower()} object.',
                'responses': {
                    204: StandardAPIResponses.no_content_204(),
                    404: StandardAPIResponses.not_found_404(),
                    **StandardAPIResponses.standard_responses()
                }
            }
        }
        
        # Apply documentation to each action
        for action_name, doc_config in action_docs.items():
            if hasattr(viewset_class, action_name):
                method = getattr(viewset_class, action_name)
                
                # Merge common kwargs
                final_config = {**common_kwargs, **doc_config}
                if tags:
                    final_config['tags'] = tags
                
                # Apply swagger decorator
                decorated_method = enhanced_swagger_auto_schema(**final_config)(method)
                setattr(viewset_class, action_name, decorated_method)
        
        return viewset_class
    
    return decorator


# ===================== SCHEMA UTILITIES =====================

class SchemaExampleGenerator:
    """Generate realistic examples for OpenAPI schemas"""
    
    @staticmethod
    def generate_user_example():
        return {
            "id": 1,
            "email": "john.doe@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "role": "sales_person",
            "is_active": True,
            "date_joined": "2024-01-15T10:30:00Z"
        }
    
    @staticmethod
    def generate_deal_example():
        return {
            "id": 1,
            "client": 1,
            "title": "Software Implementation Project",
            "description": "Implementation of CRM system for client",
            "deal_value": "150000.00",
            "commission_rate": "5.00",
            "status": "in_progress",
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-16T14:20:00Z"
        }
    
    @staticmethod
    def generate_payment_example():
        return {
            "id": 1,
            "deal": 1,
            "amount": "50000.00",
            "payment_date": "2024-01-15",
            "payment_method": "bank_transfer",
            "status": "completed",
            "notes": "Initial payment for project milestone 1"
        }


# ===================== SWAGGER INFO CONFIGURATION =====================

def get_enhanced_swagger_info():
    """Get enhanced OpenAPI info configuration"""
    return openapi.Info(
        title="Payment Receiving System API",
        default_version='v1',
        description="""
# Payment Receiving System API

Welcome to the PRS API documentation. This API provides comprehensive functionality for managing:

- **Authentication** - User login, OTP verification, session management
- **Deals** - Deal creation, tracking, and management
- **Payments** - Payment processing and tracking
- **Commission** - Commission calculation and reporting
- **Clients** - Client management and information
- **Teams** - Team management and performance tracking

## Authentication

Most endpoints require authentication using Token-based authentication:

```
Authorization: Token <your-token-here>
```

## Rate Limiting

API requests are rate limited:
- **Authenticated users**: 1000 requests/hour
- **Anonymous users**: 100 requests/hour

## Error Handling

The API uses standardized error responses with correlation IDs for tracking.

## Support

For API support: contact@prs.local
        """,
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(
            name="PRS API Support",
            email="contact@prs.local",
            url="https://prs.local/support"
        ),
        license=openapi.License(
            name="BSD License",
            url="https://opensource.org/licenses/BSD-3-Clause"
        ),
    )


# ===================== SECURITY SCHEMES =====================

def get_security_schemes():
    """Get OpenAPI security scheme definitions"""
    return {
        'Token': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'Token-based authentication. Include your token as: `Token <your-token>`'
        }
    }


# Export commonly used schemas and utilities
__all__ = [
    'EnhancedAutoSchema',
    'EnhancedFieldInspector', 
    'enhanced_swagger_auto_schema',
    'document_viewset_actions',
    'StandardAPIResponses',
    'SchemaExampleGenerator',
    'get_enhanced_swagger_info',
    'get_security_schemes',
    'success_response_schema',
    'error_response_schema',
    'auth_error_schema',
    'permission_error_schema',
    'validation_error_schema',
    'pagination_schema',
    'login_request_schema',
    'login_response_schema',
    'otp_request_schema',
    'page_parameter',
    'page_size_parameter',
    'search_parameter',
    'ordering_parameter',
    'auth_header_parameter'
]
