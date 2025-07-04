from django.contrib.auth import authenticate
from .models import User, UserSession
from .serializers import (
    UserSerializer, UserCreateSerializer, UserSessionSerializer, 
    UserLoginSerializer, UserLoginResponseSerializer, UserRegistrationSerializer, 
    UserRegistrationResponseSerializer, PasswordResetSerializer, PasswordResetResponseSerializer,
    PasswordChangeSerializer, PasswordChangeResponseSerializer, UserDetailSerializer,
    UserUpdateSerializer, LogoutResponseSerializer, SuperAdminLoginSerializer,
    SuperAdminLoginResponseSerializer, SuperAdminVerifySerializer, SuperAdminVerifyResponseSerializer,
    UserSessionDetailSerializer, ErrorResponseSerializer, AuthSuccessResponseSerializer,
    UserProfileResponseSerializer, UserLoginInitiateResponseSerializer, UserLoginVerifySerializer
)
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, viewsets, serializers, generics
from django.core.cache import cache

from django.conf import settings
import secrets
import string
import hashlib
import time
import logging
from .filters import UserFilter
from organization.models import Organization
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from permissions.models import Role
from Sales_dashboard.utils import calculate_streaks_for_user_login
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import uuid
import json
from datetime import datetime, timedelta
from django.contrib.auth import login

# Security logger
security_logger = logging.getLogger('security')

class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'

class OTPRateThrottle(AnonRateThrottle):
    scope = 'otp'

def generate_secure_otp(length=8):
    """Generate cryptographically secure OTP"""
    alphabet = string.digits + string.ascii_uppercase
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def store_otp_securely(email, otp, timeout=300):
    """Store OTP with hash and attempt limiting"""
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    cache_data = {
        'otp_hash': otp_hash,
        'created_at': time.time(),
        'attempts': 0
    }
    cache.set(f"secure_otp_{email}", cache_data, timeout=timeout)
    return True

def verify_otp_securely(email, provided_otp, max_attempts=3):
    """Verify OTP with attempt limiting"""
    cache_key = f"secure_otp_{email}"
    otp_data = cache.get(cache_key)
    
    if not otp_data:
        return False, "OTP expired or not found"
    
    if otp_data['attempts'] >= max_attempts:
        cache.delete(cache_key)
        security_logger.warning(f"OTP verification failed - too many attempts for {email}")
        return False, "Too many invalid attempts"
    
    provided_hash = hashlib.sha256(provided_otp.encode()).hexdigest()
    
    if provided_hash == otp_data['otp_hash']:
        cache.delete(cache_key)
        security_logger.info(f"OTP verification successful for {email}")
        return True, "OTP verified successfully"
    else:
        otp_data['attempts'] += 1
        cache.set(cache_key, otp_data, timeout=300)
        security_logger.warning(f"OTP verification failed for {email} - {max_attempts - otp_data['attempts']} attempts remaining")
        return False, f"Invalid OTP. {max_attempts - otp_data['attempts']} attempts remaining"

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all()
    filterset_class = UserFilter
    # permission_classes = [UserPermissions] # This needs to be defined
    throttle_classes = [UserRateThrottle]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return User.objects.none()
        user = self.request.user
        queryset = User.objects.all()
        if user.is_superuser:
            org_id = self.request.query_params.get('organization')
            if org_id:
                return queryset.filter(organization_id=org_id)
            return queryset
        if hasattr(user, 'organization') and user.organization:
            return queryset.filter(organization=user.organization)
        return User.objects.none()

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer

class UserSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows users to view and revoke their sessions.
    """
    serializer_class = UserSessionSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return UserSession.objects.none()
        return UserSession.objects.filter(user=self.request.user).order_by('-created_at')

    def destroy(self, request, *args, **kwargs):
        session = self.get_object()
        if session.user != request.user:
            return Response(
                {"error": "You can only revoke your own sessions."},
                status=status.HTTP_403_FORBIDDEN
            )
        if session.session_key == request.auth.key:
            request.auth.delete()
        session.delete()
        security_logger.info(f"Session revoked by user {request.user.email}")
        return Response(
            {"message": "Session successfully revoked."},
            status=status.HTTP_204_NO_CONTENT
        )

# Temporary storage for OTP sessions
otp_sessions = {}

@swagger_auto_schema(
    method='post',
    operation_description="Enhanced login with automatic streak calculation for salespeople",
    request_body=UserLoginSerializer,
    responses={
        200: UserLoginInitiateResponseSerializer,
        400: ErrorResponseSerializer,
        401: ErrorResponseSerializer,
        500: ErrorResponseSerializer
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def user_login_view(request):
    """
    Initiates the login process by validating credentials and sending an OTP.
    """
    serializer = UserLoginSerializer(data=request.data, context={'request': request})
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    user = serializer.validated_data['user']
    
    # Generate OTP and session
    otp = str(secrets.randbelow(900000) + 100000)  # 6-digit OTP
    session_id = str(uuid.uuid4())
    
    # Store session temporarily
    otp_sessions[session_id] = {
        'user_id': user.id,
        'otp': otp,
        'expires_at': timezone.now() + timedelta(minutes=10)
    }
    
    # Send OTP email
    try:
        send_mail(
            'Your Login OTP',
            f'Your OTP for login is: {otp}\nThis OTP will expire in 10 minutes.',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        message = 'OTP sent to your email.'
    except Exception as e:
        security_logger.error(f"Failed to send OTP email to {user.email}: {e}")
        message = 'Login initiated, but failed to send OTP email. Please check server logs.'

    # Print OTP to console for development/testing
    print(f"Login OTP for {user.email}: {otp}")
    
    return Response({
        'message': message,
        'session_id': session_id
    }, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='post',
    operation_description="Verifies the OTP to complete the login process.",
    request_body=UserLoginVerifySerializer,
    responses={
        200: AuthSuccessResponseSerializer,
        400: ErrorResponseSerializer,
        401: ErrorResponseSerializer
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def user_login_verify_view(request):
    """
    Verifies the OTP and logs in the user, returning an auth token.
    """
    serializer = UserLoginVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    session_id = serializer.validated_data['session_id']
    otp = serializer.validated_data['otp']

    session_data = otp_sessions.get(session_id)
    if not session_data or timezone.now() > session_data['expires_at'] or session_data['otp'] != otp:
        return Response({'error': 'Invalid or expired OTP.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        user = User.objects.get(id=session_data['user_id'])
        
        # Clean up session
        del otp_sessions[session_id]
        
        # Log the user in and create token
        token, created = Token.objects.get_or_create(user=user)
        user.last_login = timezone.now()
        
        # Calculate streak
        try:
            calculate_streaks_for_user_login(user)
            user.refresh_from_db()
        except Exception as e:
            security_logger.error(f"Streak calculation failed for user {user.username}: {e}")
        
        user.save(update_fields=['last_login'])
        
        user_details = UserDetailSerializer(user).data
        response_data = {
            'token': token.key,
            'user': user_details
        }
        return Response(response_data, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response({'error': 'User not found.'}, status=status.HTTP_401_UNAUTHORIZED)

@swagger_auto_schema(
    method='post',
    operation_description="Register a new user account",
    request_body=UserRegistrationSerializer,
    responses={
        201: AuthSuccessResponseSerializer,
        400: ErrorResponseSerializer
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    """
    Register a new user account, log them in, and return token and user details.
    """
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        
        user_details = UserDetailSerializer(user).data
        response_data = {
            'token': token.key,
            'user': user_details
        }
        return Response(response_data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Request password reset email",
    request_body=PasswordResetSerializer,
    responses={200: PasswordResetResponseSerializer, 400: ErrorResponseSerializer},
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_request_view(request):
    serializer = PasswordResetSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email, is_active=True)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"
            subject = 'Password Reset Request'
            message = f"Hi {user.username},\n\nPlease use this link to reset your password:\n{reset_link}\n\nIf you did not request this, please ignore this email."
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)
            return Response({'message': 'Password reset email sent successfully.', 'email': email}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'message': 'If the email exists, a reset link has been sent.'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Change user password (requires authentication)",
    request_body=PasswordChangeSerializer,
    responses={200: PasswordChangeResponseSerializer, 400: ErrorResponseSerializer, 401: "Unauthorized"},
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def password_change_view(request):
    serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='get',
    operation_description="Get current user profile information",
    responses={
        200: UserProfileResponseSerializer,
        401: "Unauthorized"
    },
    tags=['User Profile']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile_view(request):
    """
    Get authenticated user's profile information in a nested format.
    """
    user_details = UserDetailSerializer(request.user).data
    return Response({'user': user_details}, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='put',
    operation_description="Update user profile information",
    request_body=UserUpdateSerializer,
    responses={
        200: UserProfileResponseSerializer,
        400: ErrorResponseSerializer,
        401: "Unauthorized"
    },
    tags=['User Profile']
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def user_profile_update_view(request):
    """
    Update authenticated user's profile information. Returns nested user data.
    """
    serializer = UserUpdateSerializer(request.user, data=request.data, partial=True)
    if serializer.is_valid():
        user = serializer.save()
        response_serializer = UserDetailSerializer(user)
        return Response({'user': response_serializer.data}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Logout user and invalidate token",
    responses={200: LogoutResponseSerializer, 401: "Unauthorized"},
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """
    Logout user by deleting their authentication token.
    """
    try:
        Token.objects.filter(user=request.user).delete()
        return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': f'Logout failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='post',
    operation_description="Super admin first-step login (email/password validation)",
    request_body=SuperAdminLoginSerializer,
    responses={200: SuperAdminLoginResponseSerializer, 400: ErrorResponseSerializer, 401: ErrorResponseSerializer},
    tags=['Super Admin']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def super_admin_login_view(request):
    serializer = SuperAdminLoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    email = serializer.validated_data['email']
    password = serializer.validated_data['password']
    user = authenticate(email=email, password=password)
    if not user or not user.is_superuser:
        return Response({'error': 'Invalid super admin credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    otp = secrets.randbelow(900000) + 100000
    session_id = str(uuid.uuid4())
    otp_sessions[session_id] = {
        'user_id': user.id,
        'otp': str(otp),
        'expires_at': timezone.now() + timedelta(minutes=10)
    }
    try:
        send_mail('Super Admin Login OTP', f'Your OTP is: {otp}', settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
        otp_sent = True
    except Exception as e:
        security_logger.error(f"Failed to send OTP email: {e}")
        otp_sent = False
    return Response({'message': 'OTP sent to your email', 'session_id': session_id, 'otp_sent': otp_sent}, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='post',
    operation_description="Super admin second-step verification (OTP validation)",
    request_body=SuperAdminVerifySerializer,
    responses={200: SuperAdminVerifyResponseSerializer, 400: ErrorResponseSerializer, 401: ErrorResponseSerializer},
    tags=['Super Admin']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def super_admin_verify_view(request):
    serializer = SuperAdminVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    session_id = serializer.validated_data['session_id']
    otp = serializer.validated_data['otp']
    session_data = otp_sessions.get(session_id)
    if not session_data or timezone.now() > session_data['expires_at'] or session_data['otp'] != otp:
        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        user = User.objects.get(id=session_data['user_id'], is_superuser=True)
        token, created = Token.objects.get_or_create(user=user)
        del otp_sessions[session_id]
        return Response({'token': token.key, 'user_id': user.id, 'username': user.username, 'message': 'Super admin login successful'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)

@swagger_auto_schema(
    method='get',
    operation_description="Get user's active sessions (mock)",
    responses={200: UserSessionDetailSerializer(many=True), 401: "Unauthorized"},
    tags=['User Profile']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_sessions_view(request):
    # This is a mock implementation.
    current_session = {
        'id': 1, 'session_key': 'current', 'ip_address': get_client_ip(request),
        'user_agent': request.META.get('HTTP_USER_AGENT', 'Unknown'),
        'created_at': timezone.now(), 'last_activity': timezone.now()
    }
    return Response([current_session], status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='post',
    operation_description="Direct login without OTP (for development/initial setup)",
    request_body=UserLoginSerializer,
    responses={
        200: AuthSuccessResponseSerializer,
        400: ErrorResponseSerializer,
        401: ErrorResponseSerializer
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def direct_login_view(request):
    """
    Direct login without OTP verification - for development and initial setup.
    """
    serializer = UserLoginSerializer(data=request.data, context={'request': request})
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    user = serializer.validated_data['user']
    
    try:
        # Create or get token
        token, created = Token.objects.get_or_create(user=user)
        user.last_login = timezone.now()
        
        # Calculate streak
        try:
            calculate_streaks_for_user_login(user)
            user.refresh_from_db()
        except Exception as e:
            security_logger.error(f"Streak calculation failed for user {user.username}: {e}")
        
        user.save(update_fields=['last_login'])
        
        user_details = UserDetailSerializer(user).data
        response_data = {
            'token': token.key,
            'user': user_details
        }
        
        security_logger.info(f"Direct login successful for user {user.email}")
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        security_logger.error(f"Direct login failed for user {user.email}: {e}")
        return Response({'error': 'Login failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)