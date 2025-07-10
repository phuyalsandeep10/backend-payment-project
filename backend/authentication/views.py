from django.contrib.auth import authenticate
from .models import User, UserSession, UserProfile
from .serializers import (
    UserSerializer, UserCreateSerializer, UserSessionSerializer,
    UserLoginSerializer, UserRegistrationSerializer,
    PasswordChangeSerializer, UserDetailSerializer,
    UserUpdateSerializer,
    AuthSuccessResponseSerializer,
    UserProfileResponseSerializer,
    ErrorResponseSerializer,
    UserProfileSerializer,
    MessageResponseSerializer
)
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
from rest_framework.decorators import api_view, permission_classes, authentication_classes
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

# Security logger
security_logger = logging.getLogger('security')

def _create_user_session(request, user, token_key):
    """Helper to create or update a UserSession record on login."""
    # Use update_or_create to prevent IntegrityError on re-login
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
    serializer_class = UserSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]
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
    Handles new user registration.
    """
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            AuthSuccessResponseSerializer({'token': token.key, 'user': user}).data,
            status=status.HTTP_201_CREATED
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    operation_description="Change user password (requires authentication)",
    request_body=PasswordChangeSerializer,
    responses={200: MessageResponseSerializer, 400: ErrorResponseSerializer, 401: "Unauthorized"},
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

class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Handles retrieving and updating the authenticated user's profile.
    Supports GET and PUT/PATCH requests.
    """
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """Returns the authenticated user."""
        return self.request.user

    def get_serializer_class(self):
        """
        Use UserUpdateSerializer for update actions (PUT/PATCH),
        and UserDetailSerializer for retrieve actions (GET).
        """
        if self.request.method in ['PUT', 'PATCH']:
            return UserUpdateSerializer
        return UserDetailSerializer

@swagger_auto_schema(
    method='post',
    operation_description="Set the sales target for the authenticated user.",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'sales_target': openapi.Schema(type=openapi.TYPE_NUMBER, description='The new sales target.')
        },
        required=['sales_target']
    ),
    responses={200: UserDetailSerializer, 400: "Bad Request", 401: "Unauthorized"},
    tags=['User Profile']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def set_sales_target_view(request):
    """
    Sets the sales target for the authenticated user.
    """
    sales_target = request.data.get('sales_target')
    if sales_target is None:
        return Response({'error': 'sales_target is required.'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        sales_target = Decimal(sales_target)
    except (ValueError, TypeError):
        return Response({'error': 'Invalid sales_target format.'}, status=status.HTTP_400_BAD_REQUEST)

    user = request.user
    user.sales_target = sales_target
    user.save(update_fields=['sales_target'])

    serializer = UserDetailSerializer(user)
    return Response(serializer.data, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='post',
    operation_description="Logout user and invalidate token",
    responses={200: MessageResponseSerializer, 401: "Unauthorized"},
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
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
@authentication_classes([])
@csrf_exempt
def direct_login_view(request):
    """
    Logs in a user directly without OTP and returns an auth token.
    This is intended for development or specific internal use cases.
    """
    email = request.data.get('email')
    password = request.data.get('password')
    
    security_logger.info(f"Attempting direct login for email: {email}")
    
    # Manually authenticate to debug
    user = authenticate(request, username=email, password=password)
    
    if user is not None:
        security_logger.info(f"Authentication successful for user: {email}")
    else:
        security_logger.warning(f"Authentication failed for user: {email}")

    serializer = UserLoginSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Manually update the last_login field
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        token, _ = Token.objects.get_or_create(user=user)
        
        # Create a session record
        _create_user_session(request, user, token.key)

        # Trigger streak calculation upon login
        try:
            calculate_streaks_for_user_login(user)
        except Exception as e:
            # Log the error but don't block the login
            security_logger.error(f"Streak calculation failed for user {user.email}: {e}")

        return Response(
            AuthSuccessResponseSerializer({'token': token.key, 'user': user}).data,
            status=status.HTTP_200_OK
        )
    return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)

class UserProfileViewSet(viewsets.ModelViewSet):
    """
    API endpoint for users to view and edit their own profile.
    """
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        This view should return the profile of the currently authenticated user.
        """
        if not self.request.user.is_authenticated:
            return UserProfile.objects.none()
        return UserProfile.objects.filter(user=self.request.user)

    def get_object(self):
        """
        Retrieve and return the profile of the currently authenticated user.
        """
        try:
            return self.request.user.profile
        except UserProfile.DoesNotExist:
            # This can happen if a user was created before the signal was in place.
            # The signal will create it now.
            return UserProfile.objects.create(user=self.request.user)

# ===================== OTP LOGIN / VERIFY =====================


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@csrf_exempt
def super_admin_login_view(request):
    """Step 1: Super-admin submits email & password – system emails OTP."""
    email = request.data.get('email')
    password = request.data.get('password')

    user = authenticate(request, username=email, password=password)
    if not user:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_active:
        return Response({'error': 'User account disabled'}, status=status.HTTP_403_FORBIDDEN)

    # Accept either explicit Super Admin role or Django superuser flag
    if not (user.is_superuser or (
        user.role and user.role.name.lower().replace(' ', '-') == 'super-admin')):
        return Response({'error': 'User is not a super admin'}, status=status.HTTP_403_FORBIDDEN)

    otp = generate_otp()
    cache.set(f'otp:{user.id}', otp, timeout=300)  # 5 minutes
    try:
        send_otp_email(user.email, otp)
    except Exception:
        pass  # fail silently in development

    return Response({'requires_otp': True, 'user_type': 'super_admin'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@csrf_exempt
def super_admin_verify_view(request):
    """Step 2: Super-admin submits OTP – system returns token."""
    email = request.data.get('email')
    otp = request.data.get('otp')

    if not all([email, otp]):
        return Response({'error': 'email and otp are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

    expected = cache.get(f'otp:{user.id}')
    if expected != otp:
        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

    cache.delete(f'otp:{user.id}')

    # If user must change password, return temporary token instead of auth token
    if user.must_change_password:
        tmp_token = secrets.token_urlsafe(32)
        cache.set(f'tmp:{user.id}', tmp_token, timeout=600)  # 10 minutes
        return Response({
            'requires_password_change': True,
            'temporary_token': tmp_token,
            'user_type': 'super_admin',
        }, status=status.HTTP_200_OK)

    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@csrf_exempt
def org_admin_login_view(request):
    """Org-admin login step – similar but accepts any active user with Org Admin role."""
    email = request.data.get('email')
    password = request.data.get('password')

    user = authenticate(request, username=email, password=password)
    if not user:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_active:
        return Response({'error': 'User account disabled'}, status=status.HTTP_403_FORBIDDEN)

    if not user.role or user.role.name.lower() != 'org admin':
        return Response({'error': 'User is not an org admin'}, status=status.HTTP_403_FORBIDDEN)

    otp = generate_otp()
    cache.set(f'otp:{user.id}', otp, timeout=300)
    try:
        send_otp_email(user.email, otp)
    except Exception:
        pass

    return Response({'requires_otp': True, 'user_type': 'org_admin'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@csrf_exempt
def org_admin_verify_view(request):
    """Verify OTP for Org Admin."""
    email = request.data.get('email')
    otp = request.data.get('otp')

    if not all([email, otp]):
        return Response({'error': 'email and otp are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

    expected = cache.get(f'otp:{user.id}')
    if expected != otp:
        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

    cache.delete(f'otp:{user.id}')

    if user.must_change_password:
        tmp_token = secrets.token_urlsafe(32)
        cache.set(f'tmp:{user.id}', tmp_token, timeout=600)
        return Response({
            'requires_password_change': True,
            'temporary_token': tmp_token,
            'user_type': 'org_admin',
        }, status=status.HTTP_200_OK)

    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)

# ===================== PASSWORD CHANGE WITH TEMP TOKEN =====================


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@csrf_exempt
def password_change_with_token(request):
    """Allow a user with a temporary token to set a new password."""
    email = request.data.get('email')
    new_password = request.data.get('new_password')
    tmp_token = request.data.get('temporary_token')

    if not all([email, new_password, tmp_token]):
        return Response({'error': 'email, new_password and temporary_token are required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

    expected = cache.get(f'tmp:{user.id}')
    if expected != tmp_token:
        return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

    # Set new password and clear must_change_password flag
    user.set_password(new_password)
    user.must_change_password = False
    user.save(update_fields=['password', 'must_change_password'])

    cache.delete(f'tmp:{user.id}')

    token, _ = Token.objects.get_or_create(user=user)

    return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)

# ===================== EXISTING VIEWS CONTINUE BELOW =====================

# Health check for deployment services
@swagger_auto_schema(
    method='get',
    operation_description="Health check endpoint for monitoring services.",
    responses={200: "Healthy"},
    tags=['System']
)
@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Simple health check endpoint"""
    return JsonResponse({
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
        'cors_enabled': getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False),
    })

class UserNotificationPreferencesView(generics.RetrieveUpdateAPIView):
    """
    Retrieve or update the authenticated user's notification preferences.
    This view uses separate serializers for reading and writing to ensure security
    and clarity.
    """
    permission_classes = [IsAuthenticated]

    # Serializer for GET requests (reading data)
    class OutputSerializer(serializers.ModelSerializer):
        # Map camelCase field names used by the frontend to model fields
        desktopNotification = serializers.BooleanField(source='desktop_notification')
        unreadNotificationBadge = serializers.BooleanField(source='unread_notification_badge')
        pushNotificationTimeout = serializers.CharField(source='push_notification_timeout')
        communicationEmails = serializers.BooleanField(source='communication_emails')
        announcementsUpdates = serializers.BooleanField(source='announcements_updates')
        allNotificationSounds = serializers.BooleanField(source='all_notification_sounds')

        class Meta:
            model = NotificationSettings
            # Expose everything but keep camelCase aliases
            exclude = ['id', 'user', 'created_at', 'updated_at',
                       'desktop_notification', 'unread_notification_badge',
                       'push_notification_timeout', 'communication_emails',
                       'announcements_updates', 'all_notification_sounds']

    # Serializer for PUT/PATCH requests (writing data)
    class UpdateSerializer(serializers.ModelSerializer):
        # Accept camelCase fields from frontend and map to model fields
        desktopNotification = serializers.BooleanField(source='desktop_notification', required=False)
        unreadNotificationBadge = serializers.BooleanField(source='unread_notification_badge', required=False)
        pushNotificationTimeout = serializers.CharField(source='push_notification_timeout', required=False)
        communicationEmails = serializers.BooleanField(source='communication_emails', required=False)
        announcementsUpdates = serializers.BooleanField(source='announcements_updates', required=False)
        allNotificationSounds = serializers.BooleanField(source='all_notification_sounds', required=False)

        class Meta:
            model = NotificationSettings
            fields = [
                # original snake_case backend fields
                'enable_client_notifications', 'enable_deal_notifications',
                'enable_user_management_notifications', 'enable_team_notifications',
                'enable_project_notifications', 'enable_commission_notifications',
                'enable_system_notifications', 'min_priority', 'auto_mark_read_days',
                # camelCase aliases for UI
                'desktopNotification', 'unreadNotificationBadge', 'pushNotificationTimeout',
                'communicationEmails', 'announcementsUpdates', 'allNotificationSounds',
            ]

    def get_serializer_class(self):
        """
        Use the UpdateSerializer for write operations and OutputSerializer for reads.
        """
        if self.request.method in ['PUT', 'PATCH']:
            return self.UpdateSerializer
        return self.OutputSerializer

    def get_object(self):
        """
        Fetch or create the notification settings for the current user.
        """
        settings_obj, _ = NotificationSettings.objects.get_or_create(user=self.request.user)
        return settings_obj

    def update(self, request, *args, **kwargs):
        """
        Handle PATCH/PUT requests to update notification settings.

        This implementation ensures that:
        1. The incoming data is validated against the UpdateSerializer.
        2. The changes are saved to the database.
        3. The full, updated settings object is returned in the response,
           ensuring the frontend UI is correctly synchronized.
        """
        # Get the existing settings object
        instance = self.get_object()
        
        # Determine if this is a partial update (PATCH)
        partial = kwargs.pop('partial', False)
        
        # Validate incoming data with the serializer responsible for writes
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        
        # serializer.save() performs the update and returns the updated instance
        updated_instance = serializer.save()

        # Return the complete, updated data using the read-only serializer
        output_serializer = self.OutputSerializer(updated_instance)
        return Response(output_serializer.data)