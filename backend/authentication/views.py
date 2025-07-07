from django.contrib.auth import authenticate
from .models import User, UserSession, Notification, Activity, UserNotificationPreferences
from .serializers import (
    LoginSerializer, UserSerializer, UserCreateSerializer, UserSessionSerializer, 
    NotificationSerializer, ActivitySerializer, DashboardStatsSerializer,
    UserProfileSerializer, ChangePasswordSerializer, UserNotificationPreferencesSerializer
)
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, viewsets
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
import random
from .filters import UserFilter
from rest_framework.decorators import action
from django.db.models import Count, Sum
from django.utils import timezone
from datetime import timedelta
import string
from django.db.models import ProtectedError

# OTP storage backed by Django cache so it works across processes


class _OtpStore:
    """Dict-like wrapper around django cache with 5-minute default TTL."""

    DEFAULT_TTL = 300  # seconds

    def _key(self, raw: str) -> str:
        return f"otp:{raw.lower()}"

    def __setitem__(self, key: str, value: dict):
        # If the value contains an explicit 'expires', derive TTL
        ttl = self.DEFAULT_TTL
        if value and 'expires' in value:
            ttl = max(1, int((value['expires'] - timezone.now()).total_seconds()))
        cache.set(self._key(key), value, ttl)

    def __getitem__(self, key: str):
        val = cache.get(self._key(key))
        if val is None:
            raise KeyError(key)
        return val

    def __contains__(self, key: str) -> bool:
        return cache.get(self._key(key)) is not None

    def __delitem__(self, key: str):
        cache.delete(self._key(key))


otp_storage: dict[str, dict] = _OtpStore()

def _create_user_session(request, user, token):
    """
    Helper function to create a UserSession record.
    """
    # Clean up old sessions for the same user to avoid clutter
    # This is optional but good practice. You might want to limit the number of active sessions.
    UserSession.objects.filter(user=user).delete()

    ip_address = request.META.get('REMOTE_ADDR')
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
        
        # Allow all authenticated users to access their own profile, change password, and notification preferences
        if view.action in ['profile', 'change_password', 'notification_preferences']:
            return True
            
        required_perms = {
            'create': 'create_user',
            'list': 'view_user',
            'retrieve': 'view_user',
            'update': 'edit_user',
            'partial_update': 'edit_user',
            'destroy': 'delete_user',
            'change_status': 'edit_user',
        }
        
        perm_codename = required_perms.get(view.action)
        if not perm_codename:
            # Default to deny access if action not in map
            return False

        # Superusers have all permissions
        if request.user.is_superuser:
            return True
            
        # Check if the user's role has the required permission
        if request.user.role and hasattr(request.user.role, 'permissions') and request.user.role.permissions.filter(codename=perm_codename).exists():
            return True
            
        return False


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all()
    filterset_class = UserFilter
    permission_classes = [UserPermissions]

    def get_queryset(self):
        """
        This view should return a list of all the users
        for the currently authenticated user's organization.
        Superusers can see all users.
        """
        # Short-circuit for schema generation to avoid AnonymousUser errors
        if getattr(self, 'swagger_fake_view', False):
            return User.objects.none()
            
        user = self.request.user
        if user.is_superuser:
            return User.objects.all()
        return User.objects.filter(organization=user.organization)

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

    @action(detail=True, methods=['patch'])
    def change_status(self, request, pk=None):
        """
        Change user status endpoint to match frontend expectations.
        """
        user = self.get_object()
        status = request.data.get('status')
        if status not in ['active', 'inactive', 'invited', 'suspended']:
            return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)
        
        user.status = status
        user.save()
        return Response(UserSerializer(user).data)

    def destroy(self, request, *args, **kwargs):
        """Override delete to return JSON body and handle protected FK errors."""
        from django.db.models import ProtectedError
        instance = self.get_object()
        try:
            super().perform_destroy(instance)
            return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
        except ProtectedError:
            msg = (
                "Cannot delete this user because related records exist (e.g., deals, payments). "
                "Reassign or delete related data first."
            )
            return Response({"error": msg}, status=status.HTTP_409_CONFLICT)

    @action(detail=False, methods=['get', 'patch'])
    def profile(self, request):
        """
        Get or update current user's profile.
        """
        user = request.user
        
        if request.method == 'GET':
            serializer = UserProfileSerializer(user)
            return Response(serializer.data)
        
        elif request.method == 'PATCH':
            serializer = UserProfileSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def change_password(self, request):
        """
        Change password for authenticated user.
        """
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password changed successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get', 'patch'])
    def notification_preferences(self, request):
        """
        Get or update current user's notification preferences.
        """
        user = request.user
        
        # Get or create notification preferences
        preferences, created = UserNotificationPreferences.objects.get_or_create(
            user=user,
            defaults={
                'desktop_notifications': True,
                'unread_badge': False,
                'push_timeout': 'select',
                'communication_emails': True,
                'announcements_updates': False,
                'notification_sounds': True,
            }
        )
        
        if request.method == 'GET':
            serializer = UserNotificationPreferencesSerializer(preferences)
            return Response(serializer.data)
        
        elif request.method == 'PATCH':
            serializer = UserNotificationPreferencesSerializer(preferences, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(ObtainAuthToken):
    """
    Custom login view that returns user information along with token.
    """
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        # Normalize role helper
        def _norm(name: str) -> str:
            return name.lower().replace(' ', '').replace('-', '') if name else ''

        # If Super Admin, require OTP flow
        if user.is_superuser:
            return Response(
                {
                    'requires_otp': True,
                    'user_type': 'super_admin',
                    'message': 'OTP required for super admin login'
                },
                status=status.HTTP_202_ACCEPTED
            )

        # If Org Admin, require OTP flow
        if user.role and _norm(user.role.name) in ['orgadmin', 'admin']:
            return Response(
                {
                    'requires_otp': True,
                    'user_type': 'org_admin',
                    'message': 'OTP required for org admin login'
                },
                status=status.HTTP_202_ACCEPTED
            )

        # Regular users: issue token immediately
        token, _ = Token.objects.get_or_create(user=user)

        _create_user_session(request, user, token)

        return Response({'token': token.key, 'user': UserSerializer(user).data})


class LogoutView(APIView):
    """
    Logout view that invalidates the token.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Delete the user's token
            request.user.auth_token.delete()
            # Delete user sessions
            UserSession.objects.filter(user=request.user).delete()
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
        except:
            return Response({'error': 'Error logging out'}, status=status.HTTP_400_BAD_REQUEST)


class RefreshTokenView(APIView):
    """
    Refresh token view for token renewal.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Delete old token and create new one
            request.user.auth_token.delete()
            token = Token.objects.create(user=request.user)
            return Response({'token': token.key})
        except:
            return Response({'error': 'Error refreshing token'}, status=status.HTTP_400_BAD_REQUEST)


class ForgotPasswordView(APIView):
    """
    Forgot password view that sends reset email.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            # Generate OTP
            otp = ''.join(random.choices(string.digits, k=6))
            otp_storage[email] = {
                'otp': otp,
                'expires': timezone.now() + timedelta(minutes=15)
            }
            
            # Send email (in development, this will print to console)
            send_mail(
                'Password Reset OTP',
                f'Your password reset OTP is: {otp}. It will expire in 15 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            return Response({'message': 'Password reset OTP sent to your email'})
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)


class ResetPasswordView(APIView):
    """
    Reset password view using OTP.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('token')  # Frontend sends as 'token'
        password = request.data.get('password')
        
        if not all([email, otp, password]):
            return Response({'error': 'Email, token, and password are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check OTP
        if email not in otp_storage:
            return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        stored_data = otp_storage[email]
        if stored_data['otp'] != otp or timezone.now() > stored_data['expires']:
            del otp_storage[email]
            return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            
            # Clear OTP
            del otp_storage[email]
            
            return Response({'message': 'Password reset successfully'})
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class VerifyEmailView(APIView):
    """
    Email verification view.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # For now, just return success - implement proper email verification logic
        return Response({'message': 'Email verified successfully'})


class SuperAdminLoginView(APIView):
    """
    Super admin login view that sends OTP.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username') or request.data.get('email')
        password = request.data.get('password')
        
        if not username or not password:
            return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # With `USERNAME_FIELD = "email"`, pass the credential via `username` kw-arg.
        user = authenticate(username=username, password=password)
        if not user or not user.is_superuser:
            return Response({'error': 'Invalid super admin credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Generate OTP
        otp = ''.join(random.choices(string.digits, k=6))
        otp_storage[username] = {
            'otp': otp,
            'user': user,
            'expires': timezone.now() + timedelta(minutes=5)
        }
        
        # Send OTP email
        send_mail(
            'Super Admin OTP',
            f'Your super admin login OTP is: {otp}. It will expire in 5 minutes.',
            settings.DEFAULT_FROM_EMAIL,
            [settings.SUPER_ADMIN_OTP_EMAIL],
            fail_silently=False,
        )
        
        return Response({'message': 'An OTP has been sent to the designated admin email. It is valid for 5 minutes.'})


class SuperAdminVerifyOTPView(APIView):
    """
    Super admin OTP verification view.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username') or request.data.get('email')
        otp = request.data.get('otp')
        
        if not username or not otp:
            return Response({'error': 'Username and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if username not in otp_storage:
            return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        stored_data = otp_storage[username]
        if stored_data['otp'] != otp or timezone.now() > stored_data['expires']:
            del otp_storage[username]
            return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = stored_data['user']
        token, created = Token.objects.get_or_create(user=user)
        
        # Clear OTP
        del otp_storage[username]
        
        # Issue token
        token, _ = Token.objects.get_or_create(user=user)

        # If user must change password, flag and do NOT create full session
        if user.must_change_password:
            return Response({
                'requires_password_change': True,
                'temporary_token': token.key,
                'email': user.email
            }, status=status.HTTP_200_OK)

        _create_user_session(request, user, token)

        return Response({'token': token.key, 'user': UserSerializer(user).data})


class UserSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows users to view and revoke their sessions.
    """
    serializer_class = UserSessionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        This view should return a list of all the sessions
        for the currently authenticated user.
        """
        # Short-circuit for schema generation to avoid AnonymousUser errors
        if getattr(self, 'swagger_fake_view', False):
            return UserSession.objects.none()
        return UserSession.objects.filter(user=self.request.user).order_by('-created_at')

    def destroy(self, request, *args, **kwargs):
        """
        Revoke a session (delete it).
        Users can only revoke their own sessions.
        """
        session = self.get_object()
        # Prevent users from deleting their current session token, which would be confusing.
        # The frontend should ideally prevent this action.
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                current_token_key = auth_header.split(' ')[1]
                if session.session_key == current_token_key:
                    return Response({'error': 'You cannot revoke your current session.'}, status=status.HTTP_400_BAD_REQUEST)
            except IndexError:
                pass # Should not happen with token auth

        session.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class NotificationViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing user notifications.
    """
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Return notifications for the current user.
        """
        return Notification.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """
        Associate notification with current user.
        """
        serializer.save(user=self.request.user)

    def get_queryset(self):
        """
        Filter notifications and support pagination parameters.
        """
        queryset = Notification.objects.filter(user=self.request.user)
        
        # Filter by unread status
        unread = self.request.query_params.get('unread')
        if unread is not None:
            is_unread = unread.lower() == 'true'
            queryset = queryset.filter(is_read=not is_unread)
        
        return queryset

    @action(detail=True, methods=['patch'])
    def mark_read(self, request, pk=None):
        """
        Mark a notification as read.
        """
        notification = self.get_object()
        notification.is_read = True
        notification.save()
        return Response(NotificationSerializer(notification).data)


class DashboardStatsView(APIView):
    """
    API endpoint for dashboard statistics.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Return dashboard statistics based on user role.
        """
        user = request.user
        role = request.query_params.get('role', 'team-member')
        
        # Get basic stats
        if user.is_superuser:
            total_users = User.objects.count()
            from clients.models import Client
            from team.models import Team
            from commission.models import Commission
            
            total_clients = Client.objects.count()
            total_teams = Team.objects.count()
            total_commission = Commission.objects.aggregate(
                total=Sum('total_receivable')
            )['total'] or 0
        else:
            total_users = User.objects.filter(organization=user.organization).count()
            from clients.models import Client
            from team.models import Team
            from commission.models import Commission
            
            total_clients = Client.objects.filter(organization=user.organization).count()
            total_teams = Team.objects.filter(organization=user.organization).count()
            total_commission = Commission.objects.filter(
                organization=user.organization
            ).aggregate(total=Sum('total_receivable'))['total'] or 0

        # Get recent activities
        recent_activities = Activity.objects.filter(user=user)[:10]
        
        # Get notifications
        notifications = Notification.objects.filter(user=user, is_read=False)[:5]
        
        stats_data = {
            'totalUsers': total_users,
            'totalClients': total_clients,
            'totalTeams': total_teams,
            'totalCommission': total_commission,
            'recentActivities': ActivitySerializer(recent_activities, many=True).data,
            'notifications': NotificationSerializer(notifications, many=True).data,
        }
        
        return Response(stats_data)


class DashboardActivitiesView(APIView):
    """
    API endpoint for dashboard activities.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Return recent activities for the dashboard.
        """
        limit = int(request.query_params.get('limit', 10))
        activities = Activity.objects.filter(user=request.user)[:limit]
        return Response(ActivitySerializer(activities, many=True).data)


# -------------------- Org Admin OTP Views --------------------

class OrgAdminLoginView(APIView):
    """Org Admin login that sends OTP."""
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=email, password=password)
        if not user:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # Ensure user is org-admin
        def _norm(name: str) -> str:
            return name.lower().replace(' ', '').replace('-', '') if name else ''

        if not (user.role and _norm(user.role.name) in ['orgadmin', 'admin']):
            return Response({'error': 'User is not an Org Admin'}, status=status.HTTP_403_FORBIDDEN)

        # Generate OTP
        otp = ''.join(random.choices(string.digits, k=6))
        expires_at = timezone.now() + timedelta(minutes=5)
        otp_storage[email] = {
            'otp': otp,
            'user': user,
            'expires': expires_at
        }

        # Send OTP to user email
        send_mail(
            'Org Admin OTP',
            f'Your org admin login OTP is: {otp}. It will expire in 5 minutes.',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

        return Response({'message': 'An OTP has been sent to your email. It is valid for 5 minutes.'})


class OrgAdminVerifyOTPView(APIView):
    """Verify OTP for Org Admin login and issue token."""
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)

        if email not in otp_storage:
            return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

        stored = otp_storage[email]
        
        if stored['otp'] != otp:
            del otp_storage[email]
            return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
            
        if timezone.now() > stored['expires']:
            del otp_storage[email]
            return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

        user = stored['user']
        del otp_storage[email]

        # Issue token
        token, _ = Token.objects.get_or_create(user=user)

        # If user must change password, flag and do NOT create full session
        if user.must_change_password:
            return Response({
                'requires_password_change': True,
                'temporary_token': token.key,
                'email': user.email
            }, status=status.HTTP_200_OK)

        _create_user_session(request, user, token)

        return Response({'token': token.key, 'user': UserSerializer(user).data})


# -------------------- Change Password for First Login --------------------

class ChangePasswordView(APIView):
    """Change password using a temporary token issued on first login."""

    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')
        temporary_token = request.data.get('temporary_token')

        if not all([email, new_password, temporary_token]):
            return Response({'error': 'Email, new_password and temporary_token are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate token belongs to user
        try:
            from rest_framework.authtoken.models import Token
            token_obj = Token.objects.get(key=temporary_token)
            user = token_obj.user
        except Token.DoesNotExist:
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

        if user.email.lower() != email.lower():
            return Response({'error': 'Token does not match user'}, status=status.HTTP_400_BAD_REQUEST)

        # Enforce must_change_password flag
        if not user.must_change_password:
            return Response({'error': 'Password change not required'}, status=status.HTTP_400_BAD_REQUEST)

        # Update password
        user.set_password(new_password)
        user.must_change_password = False
        user.save()

        # Delete temporary token and issue new auth token
        token_obj.delete()
        new_token, _ = Token.objects.get_or_create(user=user)

        _create_user_session(request, user, new_token)

        return Response({'token': new_token.key, 'user': UserSerializer(user).data})
