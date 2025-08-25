"""
Authentication Views

This module contains all authentication-related views including:
- Login/logout views
- OTP-based authentication for admin users
- Password change functionality
- User registration

Extracted from views.py for better organization and reduced complexity.
"""

import logging
import secrets
from decimal import Decimal

from django.contrib.auth import authenticate, login
from django.core.cache import cache
from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import User, UserSession
from .serializers import (
    UserLoginSerializer, UserRegistrationSerializer, PasswordChangeSerializer,
    OTPSerializer, AuthSuccessResponseSerializer, ErrorResponseSerializer,
    MessageResponseSerializer, UserSerializer
)
from .auth_utils import LoginRateThrottle, OTPThrottle, _create_user_session, get_client_ip
from .utils import generate_otp, send_otp_email
from .response_validators import validate_response_type, ensure_drf_response, log_response_type

from core_config.error_handling import StandardErrorResponse, security_event_logger
from apps.Sales_dashboard.utils import calculate_streaks_for_user_login

# Security logger
security_logger = logging.getLogger('security')


# ===================== AUTHENTICATION FLOWS =====================

@swagger_auto_schema(
    method='post', 
    request_body=UserLoginSerializer, 
    responses={200: AuthSuccessResponseSerializer, 401: ErrorResponseSerializer}, 
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
@ensure_drf_response
@log_response_type
def login_view(request):
    """
    Unified login endpoint that handles different user roles:
    - Super Admin & Organization Admin: Sends OTP for verification
    - Other users (Salesperson, Verifier, etc.): Direct login with token
    """
    serializer = UserLoginSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Log authentication attempt
        security_event_logger.log_authentication_attempt(
            request, user.email, True
        )
        
        security_logger.info(f"Login attempt for user with role: {user.role.name if user.role else 'None'}")
        
        # Check if user is a super admin or org admin and should use OTP flow
        if user.role and ('super' in user.role.name.lower() or user.role.name.lower() == 'organization admin'):
            security_logger.info("Admin user redirected to admin login flow")
            error_response = StandardErrorResponse(
                error_code='AUTHENTICATION_ERROR',
                message='Admin users must use admin login endpoints'
            )
            return Response(error_response.to_dict(), status=status.HTTP_401_UNAUTHORIZED)
        
        # Check if user must change password
        if user.must_change_password:
            security_logger.info("User requires password change")
            tmp_token = secrets.token_urlsafe(32)
            cache.set(f'tmp:{user.id}', tmp_token, timeout=600)  # 10 minutes
            return Response({
                'requires_password_change': True, 
                'temporary_token': tmp_token, 
                'user_type': 'regular_user'
            }, status=status.HTTP_200_OK)
        
        security_logger.info(f"Login successful for user with role: {user.role.name if user.role else 'No Role'}")
        user.last_login = timezone.now()
        user.login_count += 1
        user.save(update_fields=['last_login', 'login_count'])
        token, _ = Token.objects.get_or_create(user=user)
        _create_user_session(request, user, token.key)
        try:
            calculate_streaks_for_user_login(user)
        except Exception as e:
            security_logger.error(f"Streak calculation failed for user {user.email}: {e}")
        return Response(AuthSuccessResponseSerializer({'token': token.key, 'user': user}).data, status=status.HTTP_200_OK)
    
    # Log failed authentication attempt
    email = request.data.get('email', 'unknown')
    security_event_logger.log_authentication_attempt(
        request, email, False, 'Invalid credentials'
    )
    
    error_response = StandardErrorResponse(
        error_code='AUTHENTICATION_ERROR',
        message='Invalid credentials'
    )
    return Response(error_response.to_dict(), status=status.HTTP_401_UNAUTHORIZED)


@swagger_auto_schema(
    method='post', 
    responses={200: MessageResponseSerializer}, 
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ensure_drf_response
@log_response_type
def logout_view(request):
    """Logout user by deleting their authentication token and session record."""
    try:
        if request.auth:
            UserSession.objects.filter(session_key=request.auth.key).delete()
            Token.objects.filter(key=request.auth.key).delete()
        return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
    except Exception as e:
        security_logger.error(f"Error during logout for user {request.user.email}: {e}")
        return Response({'error': 'An error occurred during logout.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@swagger_auto_schema(
    method='post', 
    request_body=OTPSerializer, 
    responses={200: AuthSuccessResponseSerializer, 400: ErrorResponseSerializer}, 
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([OTPThrottle])
@ensure_drf_response
@log_response_type
def verify_otp_view(request):
    """
    Verify OTP for admin users and complete login process
    """
    email = request.data.get('email')
    otp = request.data.get('otp')
    
    if not all([email, otp]):
        return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

    # Verify user is actually an admin
    is_admin = (
        user.is_superuser or 
        (user.role and (
            'super' in user.role.name.lower() or 
            'admin' in user.role.name.lower()
        ))
    )
    
    if not is_admin:
        return Response({'error': 'OTP verification is only for admin users'}, status=status.HTTP_400_BAD_REQUEST)

    if cache.get(f'otp:{user.id}') != otp:
        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
    
    cache.delete(f'otp:{user.id}')

    if user.must_change_password:
        tmp_token = secrets.token_urlsafe(32)
        cache.set(f'tmp:{user.id}', tmp_token, timeout=600)  # 10 minutes
        user_type = 'super_admin' if user.is_superuser else 'org_admin'
        return Response({
            'requires_password_change': True, 
            'temporary_token': tmp_token, 
            'user_type': user_type,
            'email': user.email
        }, status=status.HTTP_200_OK)

    # Complete login process
    user.last_login = timezone.now()
    user.login_count += 1
    user.save(update_fields=['last_login', 'login_count'])
    token, _ = Token.objects.get_or_create(user=user)
    _create_user_session(request, user, token.key)
    
    try:
        calculate_streaks_for_user_login(user)
    except Exception as e:
        security_logger.error(f"Streak calculation failed for user {user.email}: {e}")
    
    return Response(AuthSuccessResponseSerializer({
        'token': token.key, 
        'user': user,
        'requires_otp': False
    }).data, status=status.HTTP_200_OK)


# ===================== ADMIN LOGIN FLOWS =====================

@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
@ensure_drf_response
@log_response_type
def super_admin_login_view(request):
    """Step 1: Super-admin submits email & password – system emails OTP."""
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(request, username=email, password=password)
    if not user or not user.is_active:
        return Response({
            'error': {
                'code': 'AUTHENTICATION_ERROR',
                'message': 'Invalid credentials or user inactive'
            }
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    if not user.is_superuser and not (user.role and 'super' in user.role.name.lower()):
        return Response({
            'error': {
                'code': 'AUTHENTICATION_ERROR', 
                'message': 'Invalid credentials or not a super admin'
            }
        }, status=status.HTTP_401_UNAUTHORIZED)

    otp = generate_otp()
    cache.set(f'otp:{user.id}', otp, timeout=300)  # 5 minutes
    send_otp_email(user.email, otp)
    return Response({'message': 'OTP sent', 'requires_otp': True, 'user_type': 'super_admin'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
@ensure_drf_response
@log_response_type
def super_admin_verify_view(request):
    """Step 2: Super-admin submits OTP – system returns token or requests password change."""
    email = request.data.get('email')
    otp = request.data.get('otp')
    
    security_logger.info("Super Admin OTP verification request received")
    
    if not all([email, otp]):
        security_logger.warning("OTP verification failed: missing email or OTP")
        return Response({
            'error': {
                'code': 'BAD_REQUEST',
                'message': 'Email and OTP are required'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
        security_logger.info(f"User found with role: {user.role.name if user.role else 'None'}")
    except User.DoesNotExist:
        security_logger.warning("OTP verification failed: user not found")
        return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

    # Verify user is actually an admin
    is_admin = (
        user.is_superuser or 
        (user.role and (
            'super' in user.role.name.lower() or 
            'admin' in user.role.name.lower()
        ))
    )
    
    if not is_admin:
        security_logger.warning("OTP verification failed: admin validation failed")
        return Response({
            'error': {
                'code': 'BAD_REQUEST',
                'message': 'OTP verification is only for admin users'
            }
        }, status=status.HTTP_400_BAD_REQUEST)

    cached_otp = cache.get(f'otp:{user.id}')
    
    if cached_otp != otp:
        security_logger.warning("OTP verification failed: invalid or expired OTP")
        return Response({
            'error': {
                'code': 'BAD_REQUEST',
                'message': 'Invalid or expired OTP'
            }
        }, status=status.HTTP_400_BAD_REQUEST)
    
    cache.delete(f'otp:{user.id}')

    if user.must_change_password:
        tmp_token = secrets.token_urlsafe(32)
        cache.set(f'tmp:{user.id}', tmp_token, timeout=600)  # 10 minutes
        user_type = 'super_admin' if user.is_superuser else 'org_admin'
        return Response({
            'requires_password_change': True, 
            'temporary_token': tmp_token, 
            'user_type': user_type,
            'email': user.email
        }, status=status.HTTP_200_OK)

    # Complete login process
    token, _ = Token.objects.get_or_create(user=user)
    
    try:
        _create_user_session(request, user, token.key)
    except Exception as e:
        security_logger.error(f"Session creation failed: {e}")
    
    try:
        calculate_streaks_for_user_login(user)
    except Exception as e:
        security_logger.error(f"Streak calculation failed: {e}")
    # Use simple response to avoid UserProfile serialization issues
    return Response({
        'token': token.key,
        'user': {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': {'name': user.role.name} if user.role else None,
            'is_superuser': user.is_superuser
        },
        'requires_otp': False
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
@ensure_drf_response
@log_response_type
def org_admin_login_view(request):
    """Step 1: Org Admin submits email & password – system emails OTP."""
    email = request.data.get('email')
    password = request.data.get('password')
    
    security_logger.info("Org Admin login attempt received")
    
    user = authenticate(request, username=email, password=password)
    
    if not user or not user.is_active:
        security_logger.warning("Org Admin authentication failed or user inactive")
        return Response({'error': 'Invalid credentials or user inactive'}, status=status.HTTP_401_UNAUTHORIZED)
    
    if not user.role:
        security_logger.warning("Org Admin authentication failed: user has no role assigned")
        return Response({'error': 'User has no role assigned'}, status=status.HTTP_401_UNAUTHORIZED)
    
    security_logger.info(f"Org Admin authentication: role={user.role.name}, organization={user.organization.name if user.organization else 'None'}")
    
    if user.role.name.lower() != 'organization admin':
        security_logger.warning(f"Authentication failed: role '{user.role.name}' is not an org admin role")
        return Response({'error': 'Invalid credentials or not an org admin'}, status=status.HTTP_401_UNAUTHORIZED)
    
    security_logger.info("Org admin authentication successful, generating OTP")
    
    otp = generate_otp()
    cache.set(f'otp:{user.id}', otp, timeout=300)
    send_otp_email(user.email, otp)
    
    security_logger.info("OTP sent to user")
    
    return Response({'message': 'OTP sent', 'requires_otp': True, 'user_type': 'org_admin'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
@ensure_drf_response
@log_response_type
def org_admin_verify_view(request):
    """Step 2: Org Admin submits OTP – system returns token or requests password change."""
    email = request.data.get('email')
    otp = request.data.get('otp')
    
    security_logger.info("Org Admin OTP verification request received")
    
    if not all([email, otp]):
        security_logger.warning("OTP verification failed: missing email or OTP")
        return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
        security_logger.info(f"User found with role: {user.role.name if user.role else 'None'}")
    except User.DoesNotExist:
        security_logger.warning("OTP verification failed: user not found")
        return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

    cached_otp = cache.get(f'otp:{user.id}')
    
    if cached_otp != otp:
        security_logger.warning("OTP verification failed: invalid or expired OTP")
        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
    
    cache.delete(f'otp:{user.id}')
    security_logger.info("OTP verified successfully")

    if user.must_change_password:
        security_logger.info("User must change password, generating temporary token")
        tmp_token = secrets.token_urlsafe(32)
        cache.set(f'tmp:{user.id}', tmp_token, timeout=600)
        security_logger.info("Temporary token generated and cached")
        return Response({'requires_password_change': True, 'temporary_token': tmp_token, 'user_type': 'org_admin'}, status=status.HTTP_200_OK)

    security_logger.info("Creating authentication token")
    token, _ = Token.objects.get_or_create(user=user)
    _create_user_session(request, user, token.key)
    security_logger.info("Login successful for user")
    return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)


# ===================== PASSWORD MANAGEMENT =====================

@swagger_auto_schema(
    method='post', 
    request_body=PasswordChangeSerializer, 
    responses={200: MessageResponseSerializer, 400: ErrorResponseSerializer}, 
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ensure_drf_response
@log_response_type
def password_change_view(request):
    """Handles password change for an authenticated user."""
    serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.must_change_password = False
        user.save()
        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeWithTokenView(APIView):
    """
    Class-based view for password change with temporary token.
    Explicitly allows any user to access this endpoint.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [LoginRateThrottle]
    
    def post(self, request):
        """Allow a user with a temporary token to set a new password."""
        print(f"DEBUG: PasswordChangeWithTokenView.post called")
        print(f"DEBUG: request.user: {request.user}")
        print(f"DEBUG: request.user.is_authenticated: {getattr(request.user, 'is_authenticated', False)}")
        
        email = request.data.get('email')
        new_password = request.data.get('new_password')
        tmp_token = request.data.get('temporary_token')

        if not all([email, new_password, tmp_token]):
            return Response({'error': 'Email, new_password and temporary_token are required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

        if cache.get(f'tmp:{user.id}') != tmp_token:
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.must_change_password = False
        user.login_count += 1
        user.save(update_fields=['password', 'must_change_password', 'login_count'])
        cache.delete(f'tmp:{user.id}')
        
        token, _ = Token.objects.get_or_create(user=user)
        _create_user_session(request, user, token.key)
        return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)

# Plain Django view that bypasses DRF permission system entirely
@csrf_exempt
@require_http_methods(["POST"])
def password_change_with_token_django_view(request):
    """
    Plain Django view for password change with temporary token.
    This bypasses DRF's permission system entirely.
    """
    try:
        print(f"DEBUG: password_change_with_token_django_view called")
        print(f"DEBUG: request.method: {request.method}")
        print(f"DEBUG: request.path: {request.path}")
        
        # Parse JSON data from request body
        try:
            data = json.loads(request.body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({
                'error': 'Invalid JSON data'
            }, status=400)
        
        email = data.get('email')
        new_password = data.get('new_password')
        tmp_token = data.get('temporary_token')
        
        print(f"DEBUG: email: {email}")
        print(f"DEBUG: tmp_token present: {bool(tmp_token)}")

        if not all([email, new_password, tmp_token]):
            return JsonResponse({
                'error': 'Email, new_password and temporary_token are required.'
            }, status=400)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({
                'error': 'Invalid email'
            }, status=400)

        if cache.get(f'tmp:{user.id}') != tmp_token:
            return JsonResponse({
                'error': 'Invalid or expired token'
            }, status=400)

        user.set_password(new_password)
        user.must_change_password = False
        user.login_count += 1
        user.save(update_fields=['password', 'must_change_password', 'login_count'])
        cache.delete(f'tmp:{user.id}')
        
        token, _ = Token.objects.get_or_create(user=user)
        _create_user_session(request, user, token.key)
        
        # Calculate user_type based on role and superuser status
        user_type = 'super_admin' if user.is_superuser else 'org_admin'
        if user.role:
            role_name = user.role.name
            if role_name == 'Organization Admin':
                user_type = 'org_admin'
            elif role_name == 'Super Admin':
                user_type = 'super_admin'
            elif role_name == 'Salesperson':
                user_type = 'salesperson'
            elif role_name == 'Verifier':
                user_type = 'verifier'
            else:
                user_type = 'team_member'
        
        # Serialize user data manually
        user_data = {
            'id': user.id,
            'email': user.email,
            'user_type': user_type,
            'organization': {
                'id': user.organization.id,
                'name': user.organization.name
            } if user.organization else None,
            'must_change_password': user.must_change_password
        }
        
        return JsonResponse({
            'token': token.key, 
            'user': user_data
        }, status=200)
        
    except Exception as e:
        print(f"DEBUG: Exception in password_change_with_token_django_view: {e}")
        return JsonResponse({
            'error': 'Internal server error'
        }, status=500)

# Keep the function-based view as a wrapper for compatibility
@ensure_drf_response
@log_response_type
def password_change_with_token_view(request):
    """Function-based wrapper for the class-based view."""
    view = PasswordChangeWithTokenView()
    view.setup(request)
    return view.post(request)


# ===================== USER REGISTRATION =====================

@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
@ensure_drf_response
@log_response_type
def register_view(request):
    """Handles new user registration with enhanced input validation."""
    from core_config.security import input_validator
    from core_config.validation_schemas import ValidationSchemas
    
    try:
        # Apply comprehensive input validation
        schema = ValidationSchemas.get_endpoint_schema('auth/register', 'POST')
        if schema and request.data:
            validated_data = input_validator.validate_and_sanitize(request.data, schema)
            # Update request data with validated data
            request._mutable = True
            request.data.update(validated_data)
            request._mutable = False
    except ValidationError as e:
        security_logger.warning(f"Registration validation failed: {str(e)}")
        error_response = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            message='Input validation failed',
            details=e.message_dict if hasattr(e, 'message_dict') else str(e)
        )
        return Response(error_response.to_dict(), status=status.HTTP_400_BAD_REQUEST)
    
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)
        _create_user_session(request, user, token.key)
        return Response(AuthSuccessResponseSerializer({'token': token.key, 'user': user}).data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ===================== HEALTH CHECK =====================

@swagger_auto_schema(method='get', responses={200: "Healthy"}, tags=['System'])
@api_view(['GET'])
@permission_classes([AllowAny])
@validate_response_type
def health_check(request):
    """Simple health check endpoint for monitoring."""
    return JsonResponse({
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
        'cors_enabled': getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False),
    })


@swagger_auto_schema(method='get', responses={200: "Login Statistics"}, tags=['User Profile'])
@api_view(['GET'])
@permission_classes([IsAuthenticated])
@validate_response_type
def login_stats_view(request):
    """Get login statistics for the authenticated user."""
    from authentication.utils import get_user_login_stats
    
    stats = get_user_login_stats(request.user)
    return Response(stats, status=status.HTTP_200_OK)
