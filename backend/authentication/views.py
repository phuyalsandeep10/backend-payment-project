from django.contrib.auth import authenticate
from .models import User, UserSession
from .serializers import (
    LoginSerializer, UserSerializer, UserCreateSerializer, UserSessionSerializer, 
    UserLoginSerializer, UserLoginResponseSerializer, UserRegistrationSerializer, 
    UserRegistrationResponseSerializer, PasswordResetSerializer, PasswordResetResponseSerializer,
    PasswordChangeSerializer, PasswordChangeResponseSerializer, UserDetailSerializer,
    UserUpdateSerializer, LogoutResponseSerializer, SuperAdminLoginSerializer,
    SuperAdminLoginResponseSerializer, SuperAdminVerifySerializer, SuperAdminVerifyResponseSerializer,
    UserSessionDetailSerializer, ErrorResponseSerializer
)
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, viewsets, serializers
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

# Security logger
security_logger = logging.getLogger('security')

class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'

class OTPRateThrottle(AnonRateThrottle):
    scope = 'otp'

def generate_secure_otp(length=8):
    """Generate cryptographically secure OTP"""
    # Use secrets module for cryptographically secure random
    alphabet = string.digits + string.ascii_uppercase
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def store_otp_securely(email, otp, timeout=300):
    """Store OTP with hash and attempt limiting"""
    # Hash the OTP before storing
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
    
    # Check attempt limit
    if otp_data['attempts'] >= max_attempts:
        cache.delete(cache_key)
        security_logger.warning(f"OTP verification failed - too many attempts for {email}")
        return False, "Too many invalid attempts"
    
    # Verify OTP
    provided_hash = hashlib.sha256(provided_otp.encode()).hexdigest()
    
    if provided_hash == otp_data['otp_hash']:
        cache.delete(cache_key)
        security_logger.info(f"OTP verification successful for {email}")
        return True, "OTP verified successfully"
    else:
        # Increment attempts
        otp_data['attempts'] += 1
        cache.set(cache_key, otp_data, timeout=300)
        security_logger.warning(f"OTP verification failed for {email} - {max_attempts - otp_data['attempts']} attempts remaining")
        return False, f"Invalid OTP. {max_attempts - otp_data['attempts']} attempts remaining"

def check_rate_limit(identifier, max_attempts=5, window_minutes=15):
    """Check if identifier is within rate limits"""
    cache_key = f"rate_limit:{identifier}"
    attempts = cache.get(cache_key, 0)
    
    if attempts >= max_attempts:
        return False, f"Rate limit exceeded. Try again in {window_minutes} minutes."
    
    return True, None

def record_attempt(identifier, window_minutes=15):
    """Record an attempt for rate limiting"""
    cache_key = f"rate_limit:{identifier}"
    attempts = cache.get(cache_key, 0)
    cache.set(cache_key, attempts + 1, timeout=window_minutes * 60)

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def _create_user_session(request, user, token):
    """
    Helper function to create a UserSession record.
    """
    # Clean up old sessions for the same user to avoid clutter
    # Keep only the last 5 sessions per user
    old_sessions = UserSession.objects.filter(user=user).order_by('-created_at')[5:]
    for session in old_sessions:
        session.delete()

    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    UserSession.objects.create(
        user=user,
        session_key=token.key,
        ip_address=ip_address,
        user_agent=user_agent
    )

class UserPermissions(IsAuthenticated):
    """
    Handles permissions for the UserViewSet.
    - 'create_user': Allows creating users.
    - 'view_user': Allows listing and retrieving users.
    - 'edit_user': Allows updating users.
    - 'delete_user': Allows deleting users.
    """
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
            
        required_perms_map = {
            'create': ['create_user'],
            'list': ['view_all_users'],
            'retrieve': ['view_all_users'],
            'update': ['edit_user'],
            'partial_update': ['edit_user'],
            'destroy': ['delete_user'],
        }
        
        required_perms = required_perms_map.get(view.action, [])
        
        # Superusers have all permissions
        if request.user.is_superuser:
            return True
            
        # Check if the user's role has the required permission
        if request.user.role and request.user.role.permissions.filter(codename__in=required_perms).exists():
            return True
            
        return False


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all()
    filterset_class = UserFilter
    permission_classes = [UserPermissions]
    throttle_classes = [UserRateThrottle]

    def get_queryset(self):
        """
        This view should return a list of all the users.
        Superusers can filter by organization.
        Non-superusers are restricted to their own organization.
        """
        # Handle schema generation when user is anonymous
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

    def perform_create(self, serializer):
        """
        If the creator is not a superuser, associate the new user
        with the creator's organization.
        """
        if not self.request.user.is_superuser:
            serializer.save(organization=self.request.user.organization)
        else:
            # Superuser must provide organization in the request data
            serializer.save()

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer

# Removed redundant UserLoginView class - using function-based view with Swagger documentation

# Removed redundant LoginView class - using function-based view with Swagger documentation


# Removed redundant SuperAdminLoginView class - using function-based view with Swagger documentation


# Removed redundant SuperAdminVerifyOTPView class - using function-based view with Swagger documentation


class UserSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows users to view and revoke their sessions.
    """
    serializer_class = UserSessionSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get_queryset(self):
        """
        Users can only see their own sessions.
        """
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return UserSession.objects.none()
            
        return UserSession.objects.filter(user=self.request.user).order_by('-created_at')

    def destroy(self, request, *args, **kwargs):
        """
        Allow users to revoke (delete) their sessions.
        """
        session = self.get_object()
        
        # Additional security: Users can only delete their own sessions
        if session.user != request.user:
            return Response(
                {"error": "You can only revoke your own sessions."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # If this is the current session, also delete the token
        if session.session_key == request.auth.key:
            request.auth.delete()
        
        session.delete()
        security_logger.info(f"Session revoked by user {request.user.email}")
        
        return Response(
            {"message": "Session successfully revoked."},
            status=status.HTTP_204_NO_CONTENT
        )


# Removed redundant LogoutView class - using function-based view with Swagger documentation

# Temporary storage for OTP sessions (in production, use Redis or database)
otp_sessions = {}

@swagger_auto_schema(
    method='post',
    operation_description="Standard user login endpoint",
    request_body=LoginSerializer,
    responses={
        200: openapi.Response(
            description="Login successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'token': openapi.Schema(type=openapi.TYPE_STRING, description="Authentication token"),
                    'user_id': openapi.Schema(type=openapi.TYPE_INTEGER, description="User ID"),
                    'username': openapi.Schema(type=openapi.TYPE_STRING, description="Username"),
                    'email': openapi.Schema(type=openapi.TYPE_STRING, description="Email"),
                }
            )
        ),
        400: ErrorResponseSerializer,
        401: ErrorResponseSerializer
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """
    Standard login endpoint for user authentication.
    Returns authentication token without additional processing.
    """
    serializer = LoginSerializer(data=request.data, context={'request': request})
    
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Create or get token
        token, created = Token.objects.get_or_create(user=user)
        
        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        response_data = {
            'token': token.key,
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'organization': user.organization.name if user.organization else None,
            'role': user.role.name if user.role else None,
            'message': 'Login successful'
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Enhanced login with automatic streak calculation for salespeople",
    request_body=UserLoginSerializer,
    responses={
        200: UserLoginResponseSerializer,
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
    Enhanced login endpoint that automatically calculates and updates user streaks.
    Ideal for salespeople who need their streak updated upon login.
    """
    serializer = UserLoginSerializer(data=request.data, context={'request': request})
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = serializer.validated_data['user']
        
        # Create or get authentication token
        token, created = Token.objects.get_or_create(user=user)
        
        # Trigger automatic streak calculation
        streak_calculation_success = True
        streak_error = None
        
        try:
            calculate_streaks_for_user_login(user)
            user.refresh_from_db()  # Refresh to get updated streak
        except Exception as e:
            streak_calculation_success = False
            streak_error = str(e)
            print(f"Warning: Streak calculation failed for user {user.username}: {e}")
        
        # Update last login timestamp
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # Prepare comprehensive response
        response_data = {
            'token': token.key,
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'organization': user.organization.name if user.organization else 'No Organization',
            'role': user.role.name if user.role else 'No Role',
            'sales_target': user.sales_target or '0.00',
            'streak': user.streak,
            'last_login': user.last_login,
            'message': 'Login successful! Streak calculated and updated.' if streak_calculation_success 
                      else f'Login successful! Warning: Streak calculation failed - {streak_error}'
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {'error': f'Login failed: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@swagger_auto_schema(
    method='post',
    operation_description="Register a new user account",
    request_body=UserRegistrationSerializer,
    responses={
        201: UserRegistrationResponseSerializer,
        400: ErrorResponseSerializer
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    """
    Register a new user account with organization and role assignment.
    """
    serializer = UserRegistrationSerializer(data=request.data)
    
    if serializer.is_valid():
        user = serializer.save()
        
        response_data = {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'organization': user.organization.name if user.organization else 'No Organization',
            'message': 'User registered successfully'
        }
        
        return Response(response_data, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Request password reset email",
    request_body=PasswordResetSerializer,
    responses={
        200: PasswordResetResponseSerializer,
        400: ErrorResponseSerializer
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_request_view(request):
    """
    Send password reset email to user.
    """
    serializer = PasswordResetSerializer(data=request.data)
    
    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email, is_active=True)
            
            # Generate reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Create reset link (you'll need to implement this URL in frontend)
            reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"
            
            # Send email
            subject = 'Password Reset Request'
            message = f"""
            Hi {user.username},
            
            You requested a password reset. Click the link below to reset your password:
            {reset_link}
            
            If you didn't request this, please ignore this email.
            
            Best regards,
            PRS Team
            """
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            response_data = {
                'message': 'Password reset email sent successfully',
                'email': email
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            # For security, don't reveal if email exists
            response_data = {
                'message': 'If the email exists, a reset link will be sent',
                'email': email
            }
            return Response(response_data, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Change user password (requires authentication)",
    request_body=PasswordChangeSerializer,
    responses={
        200: PasswordChangeResponseSerializer,
        400: ErrorResponseSerializer,
        401: "Unauthorized"
    },
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def password_change_view(request):
    """
    Change authenticated user's password.
    """
    serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
    
    if serializer.is_valid():
        user = request.user
        new_password = serializer.validated_data['new_password']
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        response_data = {
            'message': 'Password changed successfully'
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='get',
    operation_description="Get current user profile information",
    responses={
        200: UserDetailSerializer,
        401: "Unauthorized"
    },
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description="Token authentication header (format: 'Token <your_token>')",
            type=openapi.TYPE_STRING,
            required=True,
            default="Token 5df12943f200cc5d1962c461bf480ff763728d95",
            example="Token 5df12943f200cc5d1962c461bf480ff763728d95"
        )
    ],
    tags=['User Profile']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile_view(request):
    """
    Get authenticated user's profile information.
    """
    serializer = UserDetailSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='put',
    operation_description="Update user profile information",
    request_body=UserUpdateSerializer,
    responses={
        200: UserDetailSerializer,
        400: ErrorResponseSerializer,
        401: "Unauthorized"
    },
    tags=['User Profile']
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def user_profile_update_view(request):
    """
    Update authenticated user's profile information.
    """
    serializer = UserUpdateSerializer(request.user, data=request.data, partial=True)
    
    if serializer.is_valid():
        user = serializer.save()
        response_serializer = UserDetailSerializer(user)
        return Response(response_serializer.data, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Logout user and invalidate token",
    responses={
        200: LogoutResponseSerializer,
        401: "Unauthorized"
    },
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description="Token authentication header (format: 'Token <your_token>')",
            type=openapi.TYPE_STRING,
            required=True,
            default="Token 5df12943f200cc5d1962c461bf480ff763728d95",
            example="Token 5df12943f200cc5d1962c461bf480ff763728d95"
        )
    ],
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """
    Logout user by deleting their authentication token.
    """
    try:
        # Delete user's token
        Token.objects.filter(user=request.user).delete()
        
        response_data = {
            'message': 'Successfully logged out'
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {'error': f'Logout failed: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@swagger_auto_schema(
    method='post',
    operation_description="Super admin first-step login (email/password validation)",
    request_body=SuperAdminLoginSerializer,
    responses={
        200: SuperAdminLoginResponseSerializer,
        400: ErrorResponseSerializer,
        401: ErrorResponseSerializer
    },
    tags=['Super Admin']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def super_admin_login_view(request):
    """
    First step of super admin login - validates credentials and sends OTP.
    """
    serializer = SuperAdminLoginSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    password = serializer.validated_data['password']
    
    # Authenticate super admin
    user = authenticate(email=email, password=password)
    
    if not user or not user.is_superuser:
        return Response(
            {'error': 'Invalid super admin credentials'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    # Generate OTP and session
    otp = secrets.randbelow(900000) + 100000  # 6-digit OTP
    session_id = str(uuid.uuid4())
    
    # Store session temporarily (expires in 5 minutes)
    otp_sessions[session_id] = {
        'user_id': user.id,
        'otp': str(otp),
        'expires_at': datetime.now() + timedelta(minutes=5)
    }
    
    # Send OTP email
    otp_sent = False
    try:
        send_mail(
            'Super Admin Login OTP',
            f'Your OTP for super admin login is: {otp}\n\nThis OTP expires in 5 minutes.',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        otp_sent = True
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
    
    response_data = {
        'message': 'OTP sent to your email' if otp_sent else 'Credentials verified, check email for OTP',
        'session_id': session_id,
        'otp_sent': otp_sent
    }
    
    return Response(response_data, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='post',
    operation_description="Super admin second-step verification (OTP validation)",
    request_body=SuperAdminVerifySerializer,
    responses={
        200: SuperAdminVerifyResponseSerializer,
        400: ErrorResponseSerializer,
        401: ErrorResponseSerializer
    },
    tags=['Super Admin']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def super_admin_verify_view(request):
    """
    Second step of super admin login - validates OTP and provides access token.
    """
    serializer = SuperAdminVerifySerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    session_id = serializer.validated_data['session_id']
    otp = serializer.validated_data['otp']
    
    # Check session
    session_data = otp_sessions.get(session_id)
    if not session_data:
        return Response(
            {'error': 'Invalid or expired session'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    # Check expiration
    if datetime.now() > session_data['expires_at']:
        del otp_sessions[session_id]
        return Response(
            {'error': 'OTP expired'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    # Validate OTP
    if session_data['otp'] != otp:
        return Response(
            {'error': 'Invalid OTP'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    # Get user and create token
    try:
        user = User.objects.get(id=session_data['user_id'], is_superuser=True)
        token, created = Token.objects.get_or_create(user=user)
        
        # Clean up session
        del otp_sessions[session_id]
        
        response_data = {
            'token': token.key,
            'user_id': user.id,
            'username': user.username,
            'message': 'Super admin login successful'
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )

@swagger_auto_schema(
    method='get',
    operation_description="Get user's active sessions",
    responses={
        200: openapi.Response(
            description="List of active sessions",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'sessions': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(type=openapi.TYPE_OBJECT)
                    ),
                    'total': openapi.Schema(type=openapi.TYPE_INTEGER)
                }
            )
        ),
        401: "Unauthorized"
    },
    tags=['User Profile']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_sessions_view(request):
    """
    Get list of user's active sessions.
    Note: This is a simplified implementation. In production, you'd track sessions in database.
    """
    # This is a mock implementation since we're using token auth
    # In a real implementation, you'd track sessions in the database
    
    current_session = {
        'id': 1,
        'session_key': 'current',
        'ip_address': request.META.get('REMOTE_ADDR', '127.0.0.1'),
        'user_agent': request.META.get('HTTP_USER_AGENT', 'Unknown'),
        'device': 'Web Browser',
        'location': 'Unknown',
        'created_at': timezone.now(),
        'last_activity': timezone.now(),
        'is_current': True
    }
    
    response_data = {
        'sessions': [current_session],
        'total': 1
    }
    
    return Response(response_data, status=status.HTTP_200_OK)