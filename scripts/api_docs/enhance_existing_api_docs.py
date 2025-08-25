#!/usr/bin/env python3
"""
Enhance Existing API Documentation

This script applies comprehensive OpenAPI documentation to existing API endpoints
by adding swagger_auto_schema decorators to views that don't have them.

Usage:
    python enhance_existing_api_docs.py --analyze
    python enhance_existing_api_docs.py --apply-auth-docs
    python enhance_existing_api_docs.py --apply-deal-docs  
    python enhance_existing_api_docs.py --apply-all
    python enhance_existing_api_docs.py --verify
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Any
import argparse

# Add Django project to path
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent / "backend"

def enhance_authentication_views():
    """Add comprehensive documentation to authentication views"""
    print("📝 Enhancing authentication views documentation...")
    
    # Read the current auth_views.py file
    auth_views_file = PROJECT_ROOT / "apps" / "authentication" / "auth_views.py"
    
    if not auth_views_file.exists():
        print("❌ auth_views.py not found")
        return False
    
    with open(auth_views_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Enhancement for login_view function
    enhanced_login_doc = '''@swagger_auto_schema(
    method='post',
    operation_summary="User Login",
    operation_description="""
    Authenticate a user and receive an authentication token.
    
    This endpoint supports regular user authentication with email and password.
    Returns a token that must be included in the Authorization header for
    subsequent API requests.
    
    **Rate Limiting**: 5 attempts per 5 minutes per IP address
    **Security**: Passwords are validated against security policy
    """,
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'password'],
        properties={
            'email': openapi.Schema(
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_EMAIL,
                description="User's email address",
                example="user@example.com"
            ),
            'password': openapi.Schema(
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_PASSWORD,
                description="User's password",
                example="securepassword123"
            )
        }
    ),
    responses={
        200: openapi.Response(
            description="Login successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'token': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="Authentication token for API requests",
                        example="9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"
                    ),
                    'user': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                            'email': openapi.Schema(type=openapi.TYPE_STRING, example="user@example.com"),
                            'first_name': openapi.Schema(type=openapi.TYPE_STRING, example="John"),
                            'last_name': openapi.Schema(type=openapi.TYPE_STRING, example="Doe"),
                            'role': openapi.Schema(type=openapi.TYPE_STRING, example="sales_person")
                        }
                    ),
                    'message': openapi.Schema(type=openapi.TYPE_STRING, example="Login successful")
                }
            )
        ),
        400: openapi.Response(
            description="Invalid credentials",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'code': openapi.Schema(type=openapi.TYPE_STRING, example="AUTHENTICATION_ERROR"),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example="Invalid credentials")
                        }
                    )
                }
            )
        ),
        429: openapi.Response(
            description="Rate limit exceeded",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="Rate limit exceeded. Try again later."
                    )
                }
            )
        )
    },
    tags=['Authentication']
)'''

    # Find the existing @swagger_auto_schema decorator for login_view
    login_pattern = r'@swagger_auto_schema\(\s*method=[\'"]post[\'"][\s\S]*?\)'
    
    if re.search(login_pattern, content):
        print("   ✅ login_view already has documentation")
    else:
        # Find the function definition and add documentation
        func_pattern = r'(@api_view\(\[\'POST\'\]\)\s*@permission_classes\(\[AllowAny\]\)[\s\S]*?def login_view\(request\):)'
        
        def replace_func(match):
            return enhanced_login_doc + '\n' + match.group(1)
        
        content = re.sub(func_pattern, replace_func, content)
        print("   📝 Added documentation to login_view")
    
    # Write back the enhanced content
    with open(auth_views_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return True


def enhance_user_views():
    """Add documentation to user management views"""
    print("📝 Enhancing user views documentation...")
    
    user_views_file = PROJECT_ROOT / "apps" / "authentication" / "user_views.py"
    
    if not user_views_file.exists():
        print("❌ user_views.py not found")
        return False
    
    with open(user_views_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Add import for swagger decorations if not present
    if 'from drf_yasg.utils import swagger_auto_schema' not in content:
        # Find import section and add swagger imports
        import_pattern = r'(from rest_framework import.*?\n)'
        swagger_import = '''from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
'''
        content = re.sub(import_pattern, f'\\1{swagger_import}', content, count=1)
        print("   📦 Added swagger imports")
    
    # Add ViewSet documentation
    viewset_doc = '''
    @swagger_auto_schema(
        methods=['get'],
        operation_summary="List Users",
        operation_description="Retrieve a paginated list of users filtered by organization",
        responses={
            200: openapi.Response("List of users", UserSerializer(many=True)),
            401: "Unauthorized",
            403: "Forbidden"
        },
        tags=['User Management']
    )'''
    
    # Look for the UserViewSet class
    if 'class UserViewSet(' in content and '@swagger_auto_schema' not in content:
        # Add documentation above the class
        class_pattern = r'(class UserViewSet\([^)]+\):)'
        content = re.sub(class_pattern, f'{viewset_doc}\\n\\1', content)
        print("   📝 Added documentation to UserViewSet")
    
    with open(user_views_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return True


def create_deal_documentation_enhancement():
    """Create enhanced documentation for deals endpoints"""
    print("📝 Creating deal documentation enhancements...")
    
    deal_docs = '''
# Deal API Documentation Enhancement
# Add these decorators to your deal views

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

# For DealViewSet
@swagger_auto_schema(
    methods=['get'],
    operation_summary="List Deals",
    operation_description="""
    Retrieve a paginated list of deals with filtering and search capabilities.
    
    **Filtering Options**:
    - `status`: Filter by deal status (pending, in_progress, completed, cancelled)
    - `client`: Filter by client ID
    - `assigned_to`: Filter by assigned user ID
    - `deal_value_min`: Minimum deal value
    - `deal_value_max`: Maximum deal value
    
    **Search**: Search in deal title and description
    **Ordering**: Sort by created_at, deal_value, status, title
    """,
    manual_parameters=[
        openapi.Parameter('status', openapi.IN_QUERY, type=openapi.TYPE_STRING,
                         enum=['pending', 'in_progress', 'completed', 'cancelled']),
        openapi.Parameter('client', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
        openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING),
        openapi.Parameter('ordering', openapi.IN_QUERY, type=openapi.TYPE_STRING),
        openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
    ],
    responses={
        200: openapi.Response(
            description="Paginated list of deals",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'count': openapi.Schema(type=openapi.TYPE_INTEGER, example=150),
                    'next': openapi.Schema(type=openapi.TYPE_STRING, example="http://api.example.com/deals/?page=2"),
                    'previous': openapi.Schema(type=openapi.TYPE_STRING),
                    'results': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                                'title': openapi.Schema(type=openapi.TYPE_STRING, example="Enterprise Software Deal"),
                                'client': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                                'deal_value': openapi.Schema(type=openapi.TYPE_STRING, example="150000.00"),
                                'status': openapi.Schema(type=openapi.TYPE_STRING, example="in_progress"),
                                'created_at': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME)
                            }
                        )
                    )
                }
            )
        ),
        401: "Unauthorized",
        403: "Forbidden"
    },
    tags=['Deals']
)
def list(self, request):
    pass

@swagger_auto_schema(
    methods=['post'],
    operation_summary="Create Deal", 
    operation_description="""
    Create a new deal in the system.
    
    **Required Fields**: title, client, deal_value
    **Optional Fields**: description, commission_rate, assigned_to
    
    **Business Rules**:
    - Deal value must be positive
    - Commission rate must be between 0 and 100
    - Client must exist and be active
    """,
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['title', 'client', 'deal_value'],
        properties={
            'title': openapi.Schema(type=openapi.TYPE_STRING, example="Enterprise Software Implementation"),
            'description': openapi.Schema(type=openapi.TYPE_STRING, example="Full CRM system implementation"),
            'client': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
            'deal_value': openapi.Schema(type=openapi.TYPE_STRING, example="150000.00"),
            'commission_rate': openapi.Schema(type=openapi.TYPE_STRING, example="5.00"),
            'assigned_to': openapi.Schema(type=openapi.TYPE_INTEGER, example=2)
        }
    ),
    responses={
        201: openapi.Response(
            description="Deal created successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'id': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                    'title': openapi.Schema(type=openapi.TYPE_STRING),
                    'client': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'deal_value': openapi.Schema(type=openapi.TYPE_STRING),
                    'status': openapi.Schema(type=openapi.TYPE_STRING, example="pending"),
                    'created_at': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME)
                }
            )
        ),
        400: "Validation error",
        401: "Unauthorized",
        403: "Forbidden"
    },
    tags=['Deals']
)
def create(self, request):
    pass
'''
    
    # Write to documentation file
    docs_dir = Path(__file__).parent / "enhancements"
    docs_dir.mkdir(exist_ok=True)
    
    deal_docs_file = docs_dir / "deal_documentation_enhancements.py"
    with open(deal_docs_file, 'w', encoding='utf-8') as f:
        f.write(deal_docs)
    
    print(f"   📄 Created deal documentation: {deal_docs_file}")
    return deal_docs_file


def create_commission_documentation_enhancement():
    """Create enhanced documentation for commission endpoints"""
    print("📝 Creating commission documentation enhancements...")
    
    commission_docs = '''
# Commission API Documentation Enhancement

@swagger_auto_schema(
    methods=['get'],
    operation_summary="List Commissions",
    operation_description="""
    Retrieve commission records with filtering and calculation details.
    
    **Key Features**:
    - Automatic commission calculation based on deal progress
    - Support for multiple commission structures
    - Real-time commission status updates
    - Payment tracking integration
    
    **Filtering**:
    - `deal`: Filter by deal ID
    - `user`: Filter by user/salesperson
    - `status`: Filter by commission status
    - `period`: Filter by time period
    """,
    manual_parameters=[
        openapi.Parameter('deal', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
        openapi.Parameter('user', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
        openapi.Parameter('status', openapi.IN_QUERY, type=openapi.TYPE_STRING,
                         enum=['pending', 'calculated', 'paid']),
        openapi.Parameter('period', openapi.IN_QUERY, type=openapi.TYPE_STRING,
                         enum=['this_month', 'last_month', 'this_quarter', 'this_year'])
    ],
    responses={
        200: openapi.Response(
            description="List of commission records",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'results': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'deal': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'user': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'commission_amount': openapi.Schema(type=openapi.TYPE_STRING, example="7500.00"),
                                'commission_rate': openapi.Schema(type=openapi.TYPE_STRING, example="5.00"),
                                'calculation_base': openapi.Schema(type=openapi.TYPE_STRING, example="150000.00"),
                                'status': openapi.Schema(type=openapi.TYPE_STRING, example="calculated"),
                                'calculated_at': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME)
                            }
                        )
                    ),
                    'summary': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'total_commission': openapi.Schema(type=openapi.TYPE_STRING, example="45000.00"),
                            'pending_amount': openapi.Schema(type=openapi.TYPE_STRING, example="15000.00"),
                            'paid_amount': openapi.Schema(type=openapi.TYPE_STRING, example="30000.00")
                        }
                    )
                }
            )
        ),
        401: "Unauthorized",
        403: "Forbidden"
    },
    tags=['Commission']
)
def list(self, request):
    pass
'''
    
    docs_dir = Path(__file__).parent / "enhancements"  
    docs_dir.mkdir(exist_ok=True)
    
    commission_docs_file = docs_dir / "commission_documentation_enhancements.py"
    with open(commission_docs_file, 'w', encoding='utf-8') as f:
        f.write(commission_docs)
    
    print(f"   📄 Created commission documentation: {commission_docs_file}")
    return commission_docs_file


def verify_documentation_coverage():
    """Verify the documentation coverage of API endpoints"""
    print("🔍 Verifying API documentation coverage...")
    
    coverage_results = {
        'total_files': 0,
        'documented_files': 0,
        'files': {}
    }
    
    # Check key API files
    api_files = [
        PROJECT_ROOT / "apps" / "authentication" / "auth_views.py",
        PROJECT_ROOT / "apps" / "authentication" / "user_views.py", 
        PROJECT_ROOT / "apps" / "authentication" / "profile_views.py",
        PROJECT_ROOT / "apps" / "deals" / "views.py",
        PROJECT_ROOT / "apps" / "commission" / "views.py",
        PROJECT_ROOT / "apps" / "clients" / "views.py",
    ]
    
    for file_path in api_files:
        if not file_path.exists():
            continue
        
        coverage_results['total_files'] += 1
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for swagger_auto_schema usage
        has_swagger = '@swagger_auto_schema' in content
        has_openapi_import = 'from drf_yasg' in content
        
        file_info = {
            'has_swagger': has_swagger,
            'has_imports': has_openapi_import,
            'documented': has_swagger and has_openapi_import
        }
        
        if file_info['documented']:
            coverage_results['documented_files'] += 1
        
        coverage_results['files'][str(file_path.relative_to(PROJECT_ROOT))] = file_info
    
    # Calculate coverage percentage
    if coverage_results['total_files'] > 0:
        coverage_percentage = (coverage_results['documented_files'] / coverage_results['total_files']) * 100
    else:
        coverage_percentage = 0
    
    print(f"📊 Documentation Coverage Results:")
    print(f"   Total API files: {coverage_results['total_files']}")
    print(f"   Documented files: {coverage_results['documented_files']}")
    print(f"   Coverage: {coverage_percentage:.1f}%")
    
    print(f"\n📋 File Status:")
    for file_path, info in coverage_results['files'].items():
        status = "✅ Documented" if info['documented'] else "❌ Needs Documentation"
        print(f"   {file_path}: {status}")
    
    return coverage_results


def create_api_testing_guide():
    """Create a guide for testing API documentation"""
    
    testing_guide = '''# API Documentation Testing Guide

## Manual Testing

### 1. Swagger UI Testing
1. Start your Django development server:
   ```bash
   python manage.py runserver
   ```

2. Navigate to Swagger UI:
   ```
   http://localhost:8000/swagger/
   ```

3. Test each endpoint:
   - ✅ All endpoints are listed
   - ✅ Request/response schemas are complete
   - ✅ Examples are realistic and helpful
   - ✅ Authentication works correctly
   - ✅ Error responses are documented

### 2. ReDoc Testing
1. Navigate to ReDoc:
   ```
   http://localhost:8000/redoc/
   ```

2. Verify:
   - ✅ Documentation is well-organized
   - ✅ Navigation works smoothly
   - ✅ All endpoints are accessible
   - ✅ Code examples are present

### 3. OpenAPI Schema Validation
1. Export the schema:
   ```bash
   curl http://localhost:8000/swagger.json > api_schema.json
   ```

2. Validate using online tools:
   - [Swagger Editor](https://editor.swagger.io/)
   - [OpenAPI Validator](https://apitools.dev/swagger-parser/)

## Automated Testing

### 1. Schema Validation Script
```python
import requests
import json

def test_openapi_schema():
    response = requests.get('http://localhost:8000/swagger.json')
    schema = response.json()
    
    # Basic schema validation
    assert 'openapi' in schema
    assert 'info' in schema
    assert 'paths' in schema
    
    # Check that all paths have documentation
    for path, methods in schema['paths'].items():
        for method, spec in methods.items():
            assert 'summary' in spec, f"Missing summary for {method.upper()} {path}"
            assert 'responses' in spec, f"Missing responses for {method.upper()} {path}"

test_openapi_schema()
print("✅ OpenAPI schema validation passed!")
```

### 2. Documentation Coverage Test
```python
def test_documentation_coverage():
    import os
    from pathlib import Path
    
    views_files = Path('apps').rglob('*views.py')
    undocumented = []
    
    for file_path in views_files:
        with open(file_path) as f:
            content = f.read()
            
        if '@api_view' in content or 'APIView' in content:
            if '@swagger_auto_schema' not in content:
                undocumented.append(str(file_path))
    
    if undocumented:
        print("❌ Undocumented API files:")
        for file in undocumented:
            print(f"   {file}")
    else:
        print("✅ All API files have documentation!")

test_documentation_coverage()
```

## Integration Testing

### 1. Test API Endpoints
```bash
# Test authentication
curl -X POST http://localhost:8000/api/auth/login/ \\
     -H "Content-Type: application/json" \\
     -d '{"email": "test@example.com", "password": "testpass123"}'

# Test with authentication token
TOKEN="your-token-here"
curl -X GET http://localhost:8000/api/deals/ \\
     -H "Authorization: Token $TOKEN"
```

### 2. Validate Response Formats
Ensure API responses match the documented schemas:

```python
import requests

def test_api_response_format():
    # Login to get token
    login_response = requests.post('http://localhost:8000/api/auth/login/', {
        'email': 'test@example.com',
        'password': 'testpass123'
    })
    
    assert login_response.status_code == 200
    data = login_response.json()
    
    # Validate response structure matches documentation
    assert 'token' in data
    assert 'user' in data
    assert 'id' in data['user']
    assert 'email' in data['user']

test_api_response_format()
```

## Quality Checklist

### Documentation Quality
- [ ] All endpoints have clear, descriptive summaries
- [ ] Request/response examples are realistic
- [ ] Error cases are documented
- [ ] Authentication requirements are clear
- [ ] Rate limiting is documented
- [ ] Deprecation notices are included where applicable

### Technical Quality
- [ ] OpenAPI schema validates successfully
- [ ] Swagger UI functions without errors
- [ ] All endpoints are reachable via documentation
- [ ] Request/response schemas match actual API behavior
- [ ] Authentication flows work in documentation

### User Experience
- [ ] Documentation is easy to navigate
- [ ] Examples help users understand the API
- [ ] Error messages are helpful
- [ ] Getting started guide is available
- [ ] Integration examples are provided
'''
    
    docs_dir = Path(__file__).parent
    testing_guide_file = docs_dir / "API_TESTING_GUIDE.md"
    
    with open(testing_guide_file, 'w', encoding='utf-8') as f:
        f.write(testing_guide)
    
    print(f"📋 Created API testing guide: {testing_guide_file}")
    return testing_guide_file


def main():
    """Main function for API documentation enhancement"""
    parser = argparse.ArgumentParser(description="Enhance API documentation")
    parser.add_argument("--analyze", action="store_true", help="Analyze current documentation coverage")
    parser.add_argument("--apply-auth-docs", action="store_true", help="Apply documentation to auth views")
    parser.add_argument("--apply-deal-docs", action="store_true", help="Create deal documentation")
    parser.add_argument("--apply-all", action="store_true", help="Apply all documentation enhancements")
    parser.add_argument("--verify", action="store_true", help="Verify documentation coverage")
    parser.add_argument("--create-testing-guide", action="store_true", help="Create API testing guide")
    
    args = parser.parse_args()
    
    if args.analyze or args.verify:
        verify_documentation_coverage()
    
    if args.apply_auth_docs or args.apply_all:
        enhance_authentication_views()
        enhance_user_views()
    
    if args.apply_deal_docs or args.apply_all:
        create_deal_documentation_enhancement()
        create_commission_documentation_enhancement()
    
    if args.create_testing_guide:
        create_api_testing_guide()
    
    if args.apply_all:
        print("\n✅ All documentation enhancements applied!")
        print("\n📚 Next Steps:")
        print("1. Review generated documentation files")
        print("2. Apply the enhancements to your views")
        print("3. Test the Swagger UI")
        print("4. Run the verification again")
    
    if not any(vars(args).values()):
        print("🎯 API Documentation Enhancement Tool")
        print("Run with --help to see all options")
        verify_documentation_coverage()


if __name__ == "__main__":
    main()
