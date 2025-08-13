"""
JWT Authentication Views
Secure authentication endpoints with httpOnly cookies
"""

import logging
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .jwt_auth import secure_token_manager, cookie_manager
from .secure_session_manager import secure_session_manager
from .error_handling import StandardErrorResponse, security_event_logger
from authentication.models import User
from authentication.utils import generate_otp, send_otp_email

# Security logger
security_logger = logging.getLogger('security')

# Request/Response schemas for documentation
login_request_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['email', 'password'],
    properties={
        'email': openapi.Schema(type=openapi.TYPE_STRING, format='email'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, format='password'),
    }
)

login_response_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
        'user': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                'role': openapi.Schema(type=openapi.TYPE_STRING),
            }
        ),
        'requires_otp': openapi.Schema(type=openapi.TYPE_BOOLEAN),
        'requires_password_change': openapi.Schema(type=openapi.TYPE_BOOLEAN),
    }
)

@swagger_auto_schema(
    method='post',
    request_body=login_request_schema,
    responses={
        200: login_response_schema,
        401: 'Authentication failed',
        400: 'Invalid request data'
    },
    tags=['JWT Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
def jwt_login(request):
    """
    JWT-based login endpoint with secure cookie authentication
    """
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        error_response = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            message='Email and password are required'
        )
        return Response(error_response.to_dict(), status=status.HTTP_400_BAD_REQUEST)
    
    # Authenticate user
    user = authenticate(request, username=email, password=password)
    
    if not user:
        # Log failed authentication
        security_event_logger.log_authentication_attempt(
            request, email, False, 'Invalid credentials'
        )
        
        error_response = StandardErrorResponse(
            error_code='AUTHENTICATION_ERROR',
            message='Invalid credentials'
        )
        return Response(error_response.to_dict(), status=status.HTTP_401_UNAUTHORIZED)
    
    if not user.is_active:
        security_event_logger.log_authentication_attempt(
            request, email, False, 'Account inactive'
        )
        
        error_response = StandardErrorResponse(
            error_code='AUTHENTICATION_ERROR',
            message='Account is inactive'
        )
        return Response(error_response.to_dict(), status=status.HTTP_401_UNAUTHORIZED)
    
    # Check if user is admin and requires OTP
    is_admin = (
        user.is_superuser or 
        (user.role and (
            'super' in user.role.name.lower() or 
            'admin' in user.role.name.lower()
        ))
    )
    
    if is_admin:
        # Generate and send OTP for admin users
        otp = generate_otp()
        cache.set(f'jwt_otp:{user.id}', otp, timeout=300)  # 5 minutes
        send_otp_email(user.email, otp)
        
        security_logger.info(f"OTP sent for admin user {user.email}")
        
        return Response({
            'success': True,
            'requires_otp': True,
            'user_type': 'super_admin' if user.is_superuser else 'org_admin',
            'message': 'OTP sent to your email'
        }, status=status.HTTP_200_OK)
    
    # Check if password change is required
    if user.must_change_password:
        # Generate temporary token for password change
        temp_tokens = secure_token_manager.generate_token_pair(user, request)
        
        # Set temporary cookies with shorter expiration
        response = Response({
            'success': True,
            'requires_password_change': True,
            'message': 'Password change required'
        }, status=status.HTTP_200_OK)
        
        # Set temporary cookies (15 minutes)
        response.set_cookie(
            'temp_access_token',
            temp_tokens['access_token'],
            max_age=900,  # 15 minutes
            httponly=True,
            secure=not settings.DEBUG,
            samesite='Strict'
        )
        
        return response
    
    # Generate JWT tokens
    tokens = secure_token_manager.generate_token_pair(user, request)
    
    # Update user login info
    user.last_login = timezone.now()
    user.login_count += 1
    user.save(update_fields=['last_login', 'login_count'])
    
    # Log successful authentication
    security_event_logger.log_authentication_attempt(
        request, email, True
    )
    
    # Create response
    response_data = {
        'success': True,
        'user': {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role.name if user.role else None,
            'organization': user.organization.name if user.organization else None,
        },
        'message': 'Login successful'
    }
    
    response = Response(response_data, status=status.HTTP_200_OK)
    
    # Set secure httpOnly cookies
    cookie_manager.set_auth_cookies(response, tokens)
    
    return response


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'otp'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, format='email'),
            'otp': openapi.Schema(type=openapi.TYPE_STRING, minLength=6, maxLength=6),
        }
    ),
    responses={
        200: login_response_schema,
        400: 'Invalid OTP or email',
        401: 'OTP verification failed'
    },
    tags=['JWT Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
def jwt_verify_otp(request):
    """
    Verify OTP for admin users and complete JWT authentication
    """
    email = request.data.get('email')
    otp = request.data.get('otp')
    
    if not email or not otp:
        error_response = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            message='Email and OTP are required'
        )
        return Response(error_response.to_dict(), status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email, is_active=True)
    except User.DoesNotExist:
        error_response = StandardErrorResponse(
            error_code='AUTHENTICATION_ERROR',
            message='Invalid email'
        )
        return Response(error_response.to_dict(), status=status.HTTP_401_UNAUTHORIZED)
    
    # Verify OTP
    cached_otp = cache.get(f'jwt_otp:{user.id}')
    if not cached_otp or cached_otp != otp:
        security_event_logger.log_authentication_attempt(
            request, email, False, 'Invalid OTP'
        )
        
        error_response = StandardErrorResponse(
            error_code='AUTHENTICATION_ERROR',
            message='Invalid or expired OTP'
        )
        return Response(error_response.to_dict(), status=status.HTTP_401_UNAUTHORIZED)
    
    # Clear OTP from cache
    cache.delete(f'jwt_otp:{user.id}')
    
    # Check if password change is required
    if user.must_change_password:
        # Generate temporary token for password change
        temp_tokens = secure_token_manager.generate_token_pair(user, request)
        
        response = Response({
            'success': True,
            'requires_password_change': True,
            'message': 'Password change required'
        }, status=status.HTTP_200_OK)
        
        # Set temporary cookies
        response.set_cookie(
            'temp_access_token',
            temp_tokens['access_token'],
            max_age=900,  # 15 minutes
            httponly=True,
            secure=not settings.DEBUG,
            samesite='Strict'
        )
        
        return response
    
    # Generate JWT tokens
    tokens = secure_token_manager.generate_token_pair(user, request)
    
    # Update user login info
    user.last_login = timezone.now()
    user.login_count += 1
    user.save(update_fields=['last_login', 'login_count'])
    
    # Log successful authentication
    security_event_logger.log_authentication_attempt(
        request, email, True
    )
    
    # Create response
    response_data = {
        'success': True,
        'user': {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role.name if user.role else None,
            'organization': user.organization.name if user.organization else None,
        },
        'message': 'Authentication successful'
    }
    
    response = Response(response_data, status=status.HTTP_200_OK)
    
    # Set secure httpOnly cookies
    cookie_manager.set_auth_cookies(response, tokens)
    
    return response


@swagger_auto_schema(
    method='post',
    responses={
        200: 'Token refreshed successfully',
        401: 'Invalid refresh token'
    },
    tags=['JWT Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
def jwt_refresh(request):
    """
    Refresh JWT access token using refresh token from httpOnly cookie
    """
    # Get refresh token from cookie
    refresh_token = cookie_manager.get_refresh_token_from_cookies(request)
    
    if not refresh_token:
        error_response = StandardErrorResponse(
            error_code='AUTHENTICATION_ERROR',
            message='Refresh token not found'
        )
        return Response(error_response.to_dict(), status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        # Refresh tokens
        new_tokens = secure_token_manager.refresh_token(refresh_token, request)
        
        # Create response
        response = Response({
            'success': True,
            'message': 'Token refreshed successfully'
        }, status=status.HTTP_200_OK)
        
        # Set new cookies
        cookie_manager.set_auth_cookies(response, new_tokens)
        
        return response
        
    except AuthenticationFailed as e:
        security_logger.warning(f"Token refresh failed: {str(e)}")
        
        error_response = StandardErrorResponse(
            error_code='AUTHENTICATION_ERROR',
            message='Invalid refresh token'
        )
        return Response(error_response.to_dict(), status=status.HTTP_401_UNAUTHORIZED)


@swagger_auto_schema(
    method='post',
    responses={
        200: 'Logout successful',
    },
    tags=['JWT Authentication']
)
@api_view(['POST'])
def jwt_logout(request):
    """
    Logout user by revoking tokens and clearing cookies
    """
    # Get tokens from cookies
    access_token = request.COOKIES.get('access_token')
    refresh_token = request.COOKIES.get('refresh_token')
    
    # Revoke tokens if they exist
    if access_token:
        secure_token_manager.revoke_token(access_token, request)
    
    if refresh_token:
        secure_token_manager.revoke_token(refresh_token, request)
    
    # Log logout
    user = getattr(request, 'user', None)
    if user and user.is_authenticated:
        security_logger.info(f"User {user.email} logged out")
    
    # Create response and clear cookies
    response = Response({
        'success': True,
        'message': 'Logout successful'
    }, status=status.HTTP_200_OK)
    
    cookie_manager.clear_auth_cookies(response)
    
    return response


@swagger_auto_schema(
    method='post',
    responses={
        200: 'All sessions revoked',
    },
    tags=['JWT Authentication']
)
@api_view(['POST'])
def jwt_logout_all(request):
    """
    Logout user from all devices by revoking all tokens
    """
    user = request.user
    
    # Revoke all user tokens
    secure_token_manager.revoke_all_user_tokens(user, request)
    
    # Log mass logout
    security_logger.warning(f"All sessions revoked for user {user.email}")
    
    # Create response and clear cookies
    response = Response({
        'success': True,
        'message': 'All sessions revoked'
    }, status=status.HTTP_200_OK)
    
    cookie_manager.clear_auth_cookies(response)
    
    return response


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['current_password', 'new_password'],
        properties={
            'current_password': openapi.Schema(type=openapi.TYPE_STRING, format='password'),
            'new_password': openapi.Schema(type=openapi.TYPE_STRING, format='password'),
        }
    ),
    responses={
        200: 'Password changed successfully',
        400: 'Invalid password data',
        401: 'Current password incorrect'
    },
    tags=['JWT Authentication']
)
@api_view(['POST'])
def jwt_change_password(request):
    """
    Change password with JWT authentication
    """
    current_password = request.data.get('current_password')
    new_password = request.data.get('new_password')
    
    if not current_password or not new_password:
        error_response = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            message='Current password and new password are required'
        )
        return Response(error_response.to_dict(), status=status.HTTP_400_BAD_REQUEST)
    
    user = request.user
    
    # Verify current password
    if not user.check_password(current_password):
        security_event_logger.log_authentication_attempt(
            request, user.email, False, 'Incorrect current password'
        )
        
        error_response = StandardErrorResponse(
            error_code='AUTHENTICATION_ERROR',
            message='Current password is incorrect'
        )
        return Response(error_response.to_dict(), status=status.HTTP_401_UNAUTHORIZED)
    
    # Validate new password strength
    if len(new_password) < 12:
        error_response = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            message='New password must be at least 12 characters long'
        )
        return Response(error_response.to_dict(), status=status.HTTP_400_BAD_REQUEST)
    
    # Change password
    user.set_password(new_password)
    user.must_change_password = False
    user.save(update_fields=['password', 'must_change_password'])
    
    # Revoke all existing tokens to force re-authentication
    secure_token_manager.revoke_all_user_tokens(user, request)
    
    # Generate new tokens
    tokens = secure_token_manager.generate_token_pair(user, request)
    
    # Log password change
    security_logger.info(f"Password changed for user {user.email}")
    
    # Create response
    response = Response({
        'success': True,
        'message': 'Password changed successfully'
    }, status=status.HTTP_200_OK)
    
    # Set new cookies
    cookie_manager.set_auth_cookies(response, tokens)
    
    return response


@swagger_auto_schema(
    method='get',
    responses={
        200: 'User profile data',
        401: 'Authentication required'
    },
    tags=['JWT Authentication']
)
@api_view(['GET'])
def jwt_user_profile(request):
    """
    Get current user profile with JWT authentication
    """
    user = request.user
    
    return Response({
        'success': True,
        'user': {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role.name if user.role else None,
            'organization': user.organization.name if user.organization else None,
            'last_login': user.last_login,
            'date_joined': user.date_joined,
            'login_count': user.login_count,
        }
    }, status=status.HTTP_200_OK)


@swagger_auto_schema(
    method='get',
    responses={
        200: 'User sessions list',
        401: 'Authentication required'
    },
    tags=['JWT Authentication']
)
@api_view(['GET'])
def jwt_user_sessions(request):
    """
    Get all active sessions for the current user
    """
    user = request.user
    
    # Get user sessions from secure session manager
    sessions = secure_session_manager.get_user_sessions(user)
    
    return Response({
        'success': True,
        'sessions': sessions,
        'total_sessions': len(sessions)
    }, status=status.HTTP_200_OK)


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['session_id'],
        properties={
            'session_id': openapi.Schema(type=openapi.TYPE_STRING),
        }
    ),
    responses={
        200: 'Session invalidated successfully',
        400: 'Invalid session ID',
        404: 'Session not found'
    },
    tags=['JWT Authentication']
)
@api_view(['POST'])
def jwt_invalidate_session(request):
    """
    Invalidate a specific session
    """
    session_id = request.data.get('session_id')
    
    if not session_id:
        error_response = StandardErrorResponse(
            error_code='VALIDATION_ERROR',
            message='Session ID is required'
        )
        return Response(error_response.to_dict(), status=status.HTTP_400_BAD_REQUEST)
    
    # Only allow users to invalidate their own sessions
    user = request.user
    user_sessions = secure_session_manager.get_user_sessions(user)
    
    # Check if session belongs to user (using truncated session ID from response)
    session_found = False
    for session in user_sessions:
        if session['session_id'].startswith(session_id[:8]):
            session_found = True
            break
    
    if not session_found:
        error_response = StandardErrorResponse(
            error_code='NOT_FOUND',
            message='Session not found or does not belong to user'
        )
        return Response(error_response.to_dict(), status=status.HTTP_404_NOT_FOUND)
    
    # Invalidate the session
    success = secure_session_manager.invalidate_session(session_id, 'user_request')
    
    if success:
        return Response({
            'success': True,
            'message': 'Session invalidated successfully'
        }, status=status.HTTP_200_OK)
    else:
        error_response = StandardErrorResponse(
            error_code='INTERNAL_ERROR',
            message='Failed to invalidate session'
        )
        return Response(error_response.to_dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@swagger_auto_schema(
    method='get',
    responses={
        200: 'Session statistics',
        403: 'Admin access required'
    },
    tags=['JWT Authentication']
)
@api_view(['GET'])
def jwt_session_statistics(request):
    """
    Get session statistics (admin only)
    """
    user = request.user
    
    # Check if user is admin
    if not (user.is_superuser or (user.role and 'admin' in user.role.name.lower())):
        error_response = StandardErrorResponse(
            error_code='PERMISSION_DENIED',
            message='Admin access required'
        )
        return Response(error_response.to_dict(), status=status.HTTP_403_FORBIDDEN)
    
    # Get session statistics
    stats = secure_session_manager.get_session_statistics()
    
    return Response({
        'success': True,
        'statistics': stats
    }, status=status.HTTP_200_OK)