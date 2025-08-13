"""
Authentication Views
- Direct Login (for development)
- OTP-based Login (for Super Admin, Org Admin)
- User Registration, Logout, Password Change
- User & Profile Management (CRUD)
- Session Management
"""
from django.contrib.auth import authenticate
from .models import User, UserSession, UserProfile
from django.core import mail

from .serializers import (
    UserSerializer, UserCreateSerializer, UserSessionSerializer,
    UserLoginSerializer, UserRegistrationSerializer,
    PasswordChangeSerializer, UserDetailSerializer,
    UserUpdateSerializer,
    AuthSuccessResponseSerializer,
    ErrorResponseSerializer,
    MessageResponseSerializer
)
from core_config.error_handling import StandardErrorResponse, security_event_logger
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework import status, viewsets, serializers, generics
from django.core.cache import cache

from django.conf import settings
import logging
from .filters import UserFilter
from organization.models import Organization
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from permissions.models import Role
from permissions.permissions import IsOrgAdminOrSuperAdmin
from Sales_dashboard.utils import calculate_streaks_for_user_login
from rest_framework.decorators import api_view, permission_classes, authentication_classes, throttle_classes
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth import login
from decimal import Decimal
import secrets

from authentication.utils import generate_otp, send_otp_email
from notifications.models import NotificationSettings
from .serializers import UserCreateSerializer, UserDetailSerializer, OTPSerializer, PasswordResetSerializer,SuperUserLoginSerializer
from rest_framework.decorators import action
from django.db import transaction

# Security logger
security_logger = logging.getLogger('security')

def get_client_ip(request):
    """Get client IP address from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def _create_user_session(request, user, token_key):
    """Helper to create or update a UserSession record on login."""
    UserSession.objects.update_or_create(
        session_key=token_key,
        defaults={
            'user': user,
            'ip_address': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')
        }
    )

class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'

class OTPThrottle(AnonRateThrottle):
    scope = 'otp'

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    Filtering by organization is handled automatically.
    Super Admins can filter by any organization using a query parameter.
    """
    queryset = User.objects.all().order_by('-date_joined')
    filterset_class = UserFilter
    permission_classes = [IsOrgAdminOrSuperAdmin]
    throttle_classes = [UserRateThrottle]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return User.objects.none()
        
        user = self.request.user
        queryset = User.objects.select_related('organization', 'role').prefetch_related('team')

        if user.is_superuser:
            org_id = self.request.query_params.get('organization')
            if org_id:
                return queryset.filter(organization_id=org_id)
            return queryset
        
        if hasattr(user, 'organization') and user.organization:
            return queryset.filter(organization=user.organization)
        
        return User.objects.none() # Should not happen for an OrgAdmin

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer

    def perform_create(self, serializer):
        user = self.request.user
        if user.is_superuser:
            organization_name = self.request.data.get('organization')
            with transaction.atomic():
                organization, created = Organization.objects.get_or_create(
                    name=organization_name,
                    defaults={'created_by': user}
                )
                # Create all required roles for the new organization
                required_roles = [
                    "Organization Admin",
                    "Salesperson",
                    "Verifier",
                    "Supervisor",
                    "Team Member"
                ]
                from permissions.models import Role
                for role_name in required_roles:
                    Role.objects.get_or_create(name=role_name, organization=organization)
                # Assign the admin role to the new user
                role, _ = Role.objects.get_or_create(name="Organization Admin", organization=organization)
                serializer.save(organization=organization, role=role)
                # Automatically assign permissions to all roles for this organization
                from django.core.management import call_command
                call_command('assign_role_permissions', organization=organization.name)
        else:
            # For non-superusers (like org admins), the organization is derived from their profile
            # and the role is taken from the request data.
            serializer.save(organization=user.organization)

class UserSessionViewSet(viewsets.ModelViewSet):
    """
    API endpoint for users to view and revoke their active sessions.
    """
    serializer_class = UserSessionSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    http_method_names = ['get', 'delete']  # Only allow GET and DELETE

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return UserSession.objects.none()
        
        # Clean up orphaned sessions (sessions without valid tokens)
        self._cleanup_orphaned_sessions()
        
        return UserSession.objects.filter(user=self.request.user).order_by('-created_at')
    
    def _cleanup_orphaned_sessions(self):
        """Remove sessions that don't have corresponding valid tokens."""
        from rest_framework.authtoken.models import Token
        
        user_sessions = UserSession.objects.filter(user=self.request.user)
        valid_token_keys = set(Token.objects.filter(user=self.request.user).values_list('key', flat=True))
        
        orphaned_sessions = user_sessions.exclude(session_key__in=valid_token_keys)
        orphaned_count = orphaned_sessions.count()
        
        if orphaned_count > 0:
            orphaned_sessions.delete()
            security_logger.info(f"Cleaned up {orphaned_count} orphaned sessions for user {self.request.user.email}")

    def destroy(self, request, *args, **kwargs):
        session = self.get_object()
        if session.user != request.user:
            return Response({"error": "You can only revoke your own sessions."}, status=status.HTTP_403_FORBIDDEN)
        
        # Find and delete the associated token
        try:
            from rest_framework.authtoken.models import Token
            token = Token.objects.get(key=session.session_key, user=session.user)
            token.delete()
            security_logger.info(f"Token {session.session_key[:8]}... deleted for user {request.user.email}")
        except Token.DoesNotExist:
            security_logger.warning(f"No token found for session {session.id} (key: {session.session_key[:8]}...)")
        
        # Delete the session record
        session.delete()
        security_logger.info(f"Session {session.id} revoked by user {request.user.email}")
        return Response({"message": "Session successfully revoked."}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
@permission_classes([AllowAny])
def test_email_outbox_view(request):
    if not settings.DEBUG:
        return Response({'error': 'Not allowed'}, status=403)
    
    # mail.outbox only exists during Django tests with locmem backend
    if hasattr(mail, 'outbox'):
        emails = []
        for email in mail.outbox:
            emails.append({
                'subject': email.subject,
                'body': email.body,
                'to': email.to,
                'from_email': email.from_email,
            })
        return Response({'outbox': emails})
    else:
        return Response({'error': 'mail.outbox is only available during Django tests with locmem email backend'}, status=400)
@swagger_auto_schema(method='post', request_body=UserRegistrationSerializer, responses={201: AuthSuccessResponseSerializer, 400: ErrorResponseSerializer}, tags=['Authentication'])
@api_view(['POST'])
@permission_classes([AllowAny])
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

@swagger_auto_schema(method='post', request_body=PasswordChangeSerializer, responses={200: MessageResponseSerializer, 400: ErrorResponseSerializer}, tags=['Authentication'])
@api_view(['POST'])
@permission_classes([IsAuthenticated])
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

class UserProfileView(generics.RetrieveUpdateAPIView):
    """Handles retrieving and updating the authenticated user's profile."""
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return UserUpdateSerializer
        return UserDetailSerializer

@swagger_auto_schema(method='post', request_body=openapi.Schema(type=openapi.TYPE_OBJECT, properties={'sales_target': openapi.Schema(type=openapi.TYPE_NUMBER)}), responses={200: UserDetailSerializer, 400: "Bad Request"}, tags=['User Profile'])
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def set_sales_target_view(request):
    """Sets the sales target for the authenticated user."""
    sales_target_str = request.data.get('sales_target')
    if sales_target_str is None:
        return Response({'error': 'sales_target field is required.'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        sales_target = Decimal(sales_target_str)
    except (ValueError, TypeError):
        return Response({'error': 'Invalid sales_target format.'}, status=status.HTTP_400_BAD_REQUEST)

    user = request.user
    user.sales_target = sales_target
    user.save(update_fields=['sales_target'])
    serializer = UserDetailSerializer(user)
    return Response(serializer.data, status=status.HTTP_200_OK)

@swagger_auto_schema(method='post', responses={200: MessageResponseSerializer}, tags=['Authentication'])
@api_view(['POST'])
@permission_classes([IsAuthenticated])
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

# ===================== AUTHENTICATION FLOWS =====================

@swagger_auto_schema(method='post', request_body=UserLoginSerializer, responses={200: AuthSuccessResponseSerializer, 401: ErrorResponseSerializer}, tags=['Authentication'])
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
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

@swagger_auto_schema(method='post', request_body=OTPSerializer, responses={200: AuthSuccessResponseSerializer, 400: ErrorResponseSerializer}, tags=['Authentication'])
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([OTPThrottle])
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

@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
def super_admin_login_view(request):
    """Step 1: Super-admin submits email & password – system emails OTP."""
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(request, username=email, password=password)
    if not user or not user.is_active:
        return Response({'error': 'Invalid credentials or user inactive'}, status=status.HTTP_401_UNAUTHORIZED)
    
    if not user.is_superuser and not (user.role and 'super' in user.role.name.lower()):
        return Response({'error': 'Invalid credentials or not a super admin'}, status=status.HTTP_401_UNAUTHORIZED)

    otp = generate_otp()
    cache.set(f'otp:{user.id}', otp, timeout=300)  # 5 minutes
    send_otp_email(user.email, otp)
    return Response({'message': 'OTP sent', 'requires_otp': True, 'user_type': 'super_admin'}, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
def super_admin_verify_view(request):
    """Step 2: Super-admin submits OTP – system returns token or requests password change."""
    email = request.data.get('email')
    otp = request.data.get('otp')
    
    security_logger.info("Super Admin OTP verification request received")
    
    if not all([email, otp]):
        security_logger.warning("OTP verification failed: missing email or OTP")
        return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)
    
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
        return Response({'error': 'OTP verification is only for admin users'}, status=status.HTTP_400_BAD_REQUEST)

    cached_otp = cache.get(f'otp:{user.id}')
    
    if cached_otp != otp:
        security_logger.warning("OTP verification failed: invalid or expired OTP")
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

@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([LoginRateThrottle])
def password_change_with_token_view(request):
    """Allow a user with a temporary token to set a new password."""
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

# ===================== MISC & HEALTH CHECK =====================

@swagger_auto_schema(method='get', responses={200: "Healthy"}, tags=['System'])
@api_view(['GET'])
@permission_classes([AllowAny])
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
def login_stats_view(request):
    """Get login statistics for the authenticated user."""
    from authentication.utils import get_user_login_stats
    
    stats = get_user_login_stats(request.user)
    return Response(stats, status=status.HTTP_200_OK)

class UserNotificationPreferencesView(generics.RetrieveUpdateAPIView):
    """Retrieve or update the authenticated user's notification preferences."""
    permission_classes = [IsAuthenticated]

    class OutputSerializer(serializers.ModelSerializer):
        desktopNotification = serializers.BooleanField(source='desktop_notification')
        unreadNotificationBadge = serializers.BooleanField(source='unread_notification_badge')
        pushNotificationTimeout = serializers.CharField(source='push_notification_timeout')
        communicationEmails = serializers.BooleanField(source='communication_emails')
        announcementsUpdates = serializers.BooleanField(source='announcements_updates')
        allNotificationSounds = serializers.BooleanField(source='all_notification_sounds')
        class Meta:
            model = NotificationSettings
            exclude = ['id', 'user', 'created_at', 'updated_at', 'desktop_notification', 'unread_notification_badge', 'push_notification_timeout', 'communication_emails', 'announcements_updates', 'all_notification_sounds']

    class UpdateSerializer(serializers.ModelSerializer):
        desktopNotification = serializers.BooleanField(source='desktop_notification', required=False)
        unreadNotificationBadge = serializers.BooleanField(source='unread_notification_badge', required=False)
        pushNotificationTimeout = serializers.CharField(source='push_notification_timeout', required=False)
        communicationEmails = serializers.BooleanField(source='communication_emails', required=False)
        announcementsUpdates = serializers.BooleanField(source='announcements_updates', required=False)
        allNotificationSounds = serializers.BooleanField(source='all_notification_sounds', required=False)
        class Meta:
            model = NotificationSettings
            fields = ['enable_client_notifications', 'enable_deal_notifications', 'enable_user_management_notifications', 'enable_team_notifications', 'enable_project_notifications', 'enable_commission_notifications', 'enable_system_notifications', 'min_priority', 'auto_mark_read_days', 'desktopNotification', 'unreadNotificationBadge', 'pushNotificationTimeout', 'communicationEmails', 'announcementsUpdates', 'allNotificationSounds']

    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return self.UpdateSerializer
        return self.OutputSerializer

    def get_object(self):
        settings_obj, _ = NotificationSettings.objects.get_or_create(user=self.request.user)
        return settings_obj