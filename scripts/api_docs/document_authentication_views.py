#!/usr/bin/env python3
"""
Authentication Views Documentation Enhancement

This script demonstrates how to properly document authentication views
using the enhanced swagger configuration.

Usage:
    python document_authentication_views.py
"""

import sys
from pathlib import Path

# Add the backend to the path
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent / "backend"
sys.path.insert(0, str(PROJECT_ROOT))

# Documentation examples for authentication views
AUTHENTICATION_DOCUMENTATION = '''
"""
Enhanced Authentication Views with Complete OpenAPI Documentation

This file shows how to properly document authentication endpoints
using our enhanced swagger configuration.
"""

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

# Import enhanced swagger utilities
from core_config.enhanced_swagger_config import (
    enhanced_swagger_auto_schema,
    StandardAPIResponses,
    SchemaExampleGenerator,
    login_request_schema,
    login_response_schema,
    otp_request_schema,
    auth_header_parameter
)

# ===================== LOGIN ENDPOINT =====================

@swagger_auto_schema(
    method='post',
    operation_summary="User Login",
    operation_description="""
    Authenticate a user and receive an authentication token.
    
    This endpoint supports regular user authentication with email and password.
    Upon successful authentication, returns a token that must be included
    in the Authorization header for subsequent API requests.
    
    **Rate Limiting**: 5 attempts per 5 minutes per IP address
    
    **Example Usage**:
    ```bash
    curl -X POST http://localhost:8000/api/auth/login/ \\
         -H "Content-Type: application/json" \\
         -d '{"email": "user@example.com", "password": "securepass123"}'
    ```
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
                        description="Authentication token",
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
                    'message': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="Login successful"
                    )
                }
            ),
            examples={
                'application/json': {
                    'token': '9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b',
                    'user': {
                        'id': 1,
                        'email': 'user@example.com',
                        'first_name': 'John',
                        'last_name': 'Doe', 
                        'role': 'sales_person'
                    },
                    'message': 'Login successful'
                }
            }
        ),
        400: openapi.Response(
            description="Invalid credentials or validation error",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'code': openapi.Schema(type=openapi.TYPE_STRING, example="AUTHENTICATION_ERROR"),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example="Invalid credentials"),
                            'details': openapi.Schema(type=openapi.TYPE_OBJECT)
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
                        example="Rate limit exceeded. Try again in 5 minutes."
                    )
                }
            )
        )
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """User login endpoint with token authentication"""
    # Implementation here
    pass

# ===================== ADMIN LOGIN (STEP 1) =====================

@swagger_auto_schema(
    method='post',
    operation_summary="Admin Login - Step 1",
    operation_description="""
    First step of admin authentication with OTP.
    
    This endpoint initiates the admin login process by validating credentials
    and sending an OTP (One-Time Password) to the admin's registered email.
    
    **Admin Types**:
    - Super Admin: Full system access
    - Organization Admin: Organization-scoped access
    
    **Security Features**:
    - OTP expires in 5 minutes
    - Rate limited to prevent brute force attacks
    - Secure OTP generation and delivery
    
    **Next Step**: Use `/api/auth/login/super-admin/verify/` with the OTP
    """,
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'password'],
        properties={
            'email': openapi.Schema(
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_EMAIL,
                description="Admin user's email address",
                example="admin@example.com"
            ),
            'password': openapi.Schema(
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_PASSWORD,
                description="Admin user's password", 
                example="adminsecurepass123"
            )
        }
    ),
    responses={
        200: openapi.Response(
            description="OTP sent successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="OTP sent to your registered email"
                    ),
                    'expires_in': openapi.Schema(
                        type=openapi.TYPE_INTEGER,
                        description="OTP expiration time in seconds",
                        example=300
                    )
                }
            )
        ),
        400: openapi.Response(description="Invalid credentials"),
        401: openapi.Response(description="Unauthorized - not an admin user"),
        429: openapi.Response(description="Rate limit exceeded")
    },
    tags=['Authentication', 'Admin']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def super_admin_login_view(request):
    """Super admin login - step 1: credential validation and OTP generation"""
    pass

# ===================== ADMIN LOGIN (STEP 2) =====================

@swagger_auto_schema(
    method='post',
    operation_summary="Admin Login - Step 2 (OTP Verification)",
    operation_description="""
    Second step of admin authentication - OTP verification.
    
    This endpoint completes the admin login process by verifying the OTP
    sent to the admin's email and returning an authentication token.
    
    **OTP Requirements**:
    - Must be used within 5 minutes of generation
    - 6-digit numeric code
    - Single use only (expires after successful verification)
    
    **Security Features**:
    - Prevents replay attacks
    - Logs all authentication attempts
    - Automatic cleanup of expired OTPs
    """,
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'otp'],
        properties={
            'email': openapi.Schema(
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_EMAIL,
                description="Admin user's email address (same as step 1)",
                example="admin@example.com"
            ),
            'otp': openapi.Schema(
                type=openapi.TYPE_STRING,
                description="6-digit OTP code from email",
                example="123456",
                minLength=6,
                maxLength=6,
                pattern="^[0-9]{6}$"
            )
        }
    ),
    responses={
        200: openapi.Response(
            description="Admin authentication successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'token': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="Admin authentication token",
                        example="admin_9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"
                    ),
                    'user': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                            'email': openapi.Schema(type=openapi.TYPE_STRING, example="admin@example.com"),
                            'first_name': openapi.Schema(type=openapi.TYPE_STRING, example="Admin"),
                            'last_name': openapi.Schema(type=openapi.TYPE_STRING, example="User"),
                            'role': openapi.Schema(type=openapi.TYPE_STRING, example="super_admin"),
                            'permissions': openapi.Schema(
                                type=openapi.TYPE_ARRAY,
                                items=openapi.Schema(type=openapi.TYPE_STRING),
                                example=["manage_users", "view_reports", "system_admin"]
                            )
                        }
                    ),
                    'session': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'expires_at': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                format=openapi.FORMAT_DATETIME,
                                example="2024-01-16T10:30:00Z"
                            ),
                            'session_id': openapi.Schema(
                                type=openapi.TYPE_STRING,
                                example="sess_abc123def456"
                            )
                        }
                    )
                }
            )
        ),
        400: openapi.Response(
            description="Invalid or expired OTP",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'code': openapi.Schema(type=openapi.TYPE_STRING, example="INVALID_OTP"),
                            'message': openapi.Schema(type=openapi.TYPE_STRING, example="Invalid or expired OTP"),
                        }
                    )
                }
            )
        ),
        404: openapi.Response(description="OTP not found or expired"),
        429: openapi.Response(description="Too many verification attempts")
    },
    tags=['Authentication', 'Admin']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def super_admin_verify_view(request):
    """Super admin OTP verification - step 2 of admin login"""
    pass

# ===================== USER PROFILE =====================

@swagger_auto_schema(
    method='get',
    operation_summary="Get User Profile",
    operation_description="""
    Retrieve the authenticated user's profile information.
    
    Returns comprehensive user profile data including:
    - Basic information (name, email, role)
    - Profile settings and preferences
    - Account status and permissions
    - Organization membership details
    """,
    manual_parameters=[auth_header_parameter],
    responses={
        200: openapi.Response(
            description="User profile data",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'id': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                    'email': openapi.Schema(type=openapi.TYPE_STRING, example="user@example.com"),
                    'first_name': openapi.Schema(type=openapi.TYPE_STRING, example="John"),
                    'last_name': openapi.Schema(type=openapi.TYPE_STRING, example="Doe"),
                    'role': openapi.Schema(type=openapi.TYPE_STRING, example="sales_person"),
                    'organization': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                            'name': openapi.Schema(type=openapi.TYPE_STRING, example="Example Corp")
                        }
                    ),
                    'profile': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'phone': openapi.Schema(type=openapi.TYPE_STRING, example="+1234567890"),
                            'sales_target': openapi.Schema(type=openapi.TYPE_STRING, example="50000.00"),
                            'notification_preferences': openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'email_notifications': openapi.Schema(type=openapi.TYPE_BOOLEAN, example=True),
                                    'deal_updates': openapi.Schema(type=openapi.TYPE_BOOLEAN, example=True)
                                }
                            )
                        }
                    ),
                    'permissions': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(type=openapi.TYPE_STRING),
                        example=["create_deals", "view_commission", "edit_profile"]
                    ),
                    'last_login': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        format=openapi.FORMAT_DATETIME,
                        example="2024-01-15T10:30:00Z"
                    )
                }
            )
        ),
        401: StandardAPIResponses.unauthorized_401(),
        500: StandardAPIResponses.server_error_500()
    },
    tags=['Profile', 'User Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile_view(request):
    """Get authenticated user's profile"""
    pass

# ===================== LOGOUT =====================

@swagger_auto_schema(
    method='post',
    operation_summary="User Logout",
    operation_description="""
    Log out the authenticated user and invalidate their token.
    
    This endpoint:
    - Invalidates the current authentication token
    - Clears user session data
    - Logs the logout event for security auditing
    
    After logout, the token can no longer be used for authentication.
    """,
    manual_parameters=[auth_header_parameter],
    responses={
        200: openapi.Response(
            description="Logout successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="Logout successful"
                    )
                }
            )
        ),
        401: StandardAPIResponses.unauthorized_401()
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """User logout endpoint"""
    pass

'''

# ViewSet documentation example
VIEWSET_DOCUMENTATION_EXAMPLE = '''
# ===================== USER VIEWSET DOCUMENTATION =====================

from rest_framework import viewsets
from core_config.enhanced_swagger_config import document_viewset_actions

@document_viewset_actions(
    tags=['User Management'],
    operation_id_base='users'
)
class UserViewSet(viewsets.ModelViewSet):
    """
    User management ViewSet with full CRUD operations.
    
    Provides endpoints for:
    - Listing users (with filtering and pagination)
    - Retrieving individual user details
    - Creating new users (admin only)
    - Updating user information
    - Deleting users (admin only)
    
    **Permissions**: 
    - List/Retrieve: Authenticated users (filtered by organization)
    - Create/Update/Delete: Admin users only
    
    **Filtering**: 
    - Search by name or email
    - Filter by role, organization, active status
    - Order by name, email, date_joined
    """
    
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['role', 'is_active', 'organization']
    search_fields = ['first_name', 'last_name', 'email']
    ordering_fields = ['first_name', 'last_name', 'email', 'date_joined']
    ordering = ['last_name', 'first_name']
    
    # The @document_viewset_actions decorator automatically adds
    # appropriate swagger documentation to all CRUD methods
'''


def create_documentation_examples():
    """Create documentation example files"""
    
    # Create examples directory
    examples_dir = Path(__file__).parent / "examples"
    examples_dir.mkdir(exist_ok=True)
    
    # Write authentication documentation example
    auth_example_file = examples_dir / "documented_authentication_views.py"
    with open(auth_example_file, 'w', encoding='utf-8') as f:
        f.write(AUTHENTICATION_DOCUMENTATION)
    
    # Write viewset documentation example  
    viewset_example_file = examples_dir / "documented_viewset_example.py"
    with open(viewset_example_file, 'w', encoding='utf-8') as f:
        f.write(VIEWSET_DOCUMENTATION_EXAMPLE)
    
    print(f"✅ Created documentation examples:")
    print(f"   📄 {auth_example_file}")
    print(f"   📄 {viewset_example_file}")
    
    return [auth_example_file, viewset_example_file]


def generate_documentation_checklist():
    """Generate a checklist for API documentation"""
    
    checklist = '''# API Documentation Checklist

Use this checklist to ensure comprehensive API documentation:

## ✅ For Each Endpoint

### Basic Documentation
- [ ] `@swagger_auto_schema` decorator applied
- [ ] Clear `operation_summary` (max 50 characters)  
- [ ] Detailed `operation_description` with examples
- [ ] Appropriate `tags` for grouping
- [ ] All HTTP methods documented

### Request Documentation
- [ ] Request body schema defined (for POST/PUT/PATCH)
- [ ] All required fields marked as required
- [ ] Field descriptions with examples
- [ ] Validation rules documented
- [ ] File upload endpoints have multipart/form-data

### Response Documentation  
- [ ] All possible response codes documented
- [ ] Success response schemas defined
- [ ] Error response schemas included
- [ ] Response examples provided
- [ ] Pagination schema for list endpoints

### Security Documentation
- [ ] Authentication requirements specified
- [ ] Permission classes documented
- [ ] Rate limiting information included
- [ ] Security considerations noted

### Additional Documentation
- [ ] Query parameters documented
- [ ] Path parameters documented  
- [ ] Filtering options explained
- [ ] Ordering options explained
- [ ] Search functionality documented

## ✅ For Each Module

### Module-Level Documentation
- [ ] Module overview in docstring
- [ ] Key endpoints listed
- [ ] Business logic explained
- [ ] Data relationships documented

### Integration Documentation
- [ ] Usage examples provided
- [ ] SDK examples for popular languages
- [ ] Error handling examples
- [ ] Authentication flow examples

## ✅ Overall API Documentation

### OpenAPI Schema
- [ ] API info complete (title, description, version)
- [ ] Server URLs configured
- [ ] Security schemes defined
- [ ] Contact information provided
- [ ] License information included

### Interactive Documentation
- [ ] Swagger UI accessible and functional
- [ ] ReDoc available as alternative
- [ ] Try-it-out functionality works
- [ ] Examples execute successfully

### Integration Guides
- [ ] Getting started guide
- [ ] Authentication guide  
- [ ] Error handling guide
- [ ] Rate limiting guide
- [ ] SDK and code examples

### Maintenance
- [ ] Documentation CI/CD pipeline
- [ ] Automated documentation testing
- [ ] Version management strategy
- [ ] Deprecation notices for old endpoints
'''
    
    checklist_file = Path(__file__).parent / "API_DOCUMENTATION_CHECKLIST.md"
    with open(checklist_file, 'w', encoding='utf-8') as f:
        f.write(checklist)
    
    print(f"📋 Created documentation checklist: {checklist_file}")
    return checklist_file


def main():
    """Main function to create all documentation resources"""
    print("🚀 Creating API Documentation Resources...")
    
    # Create example files
    example_files = create_documentation_examples()
    
    # Create checklist
    checklist_file = generate_documentation_checklist()
    
    print("\n✅ API Documentation Resources Created!")
    print("\n📚 Next Steps:")
    print("1. Review the example files for proper documentation patterns")
    print("2. Apply similar documentation to your API views")
    print("3. Use the checklist to ensure comprehensive coverage")
    print("4. Test the Swagger UI to verify documentation quality")
    print("5. Update documentation as you add new endpoints")
    
    print(f"\n🔗 Access your API documentation at:")
    print(f"   - Swagger UI: http://localhost:8000/swagger/")
    print(f"   - ReDoc: http://localhost:8000/redoc/")


if __name__ == "__main__":
    main()
