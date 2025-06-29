from django.contrib.auth import authenticate
from .models import User, UserSession
from .serializers import LoginSerializer, UserSerializer, UserCreateSerializer, UserSessionSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework import status, viewsets, serializers
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
import secrets
import string
import hashlib
import time
import logging
from .filters import UserFilter
from organization.models import Organization
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle

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
        user = self.request.user
        queryset = User.objects.all()

        if user.is_superuser:
            org_id = self.request.query_params.get('organization')
            if org_id:
                return queryset.filter(organization_id=org_id)
            return queryset

        if user.organization:
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

class LoginView(APIView):
    permission_classes = []
    throttle_classes = [LoginRateThrottle]

    def post(self, request, *args, **kwargs):
        client_ip = get_client_ip(request)
        
        # Check rate limiting
        allowed, message = check_rate_limit(client_ip, max_attempts=5, window_minutes=15)
        if not allowed:
            security_logger.warning(f"Login rate limit exceeded for IP {client_ip}")
            return Response({'error': message}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        serializer = LoginSerializer(data=request.data, context={'request': request})
        
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            _create_user_session(request, user, token)
            
            security_logger.info(f"Successful login for user {user.email} from IP {client_ip}")
            
            return Response({
                'token': token.key,
                'user': UserSerializer(user).data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            # Record failed attempt
            record_attempt(client_ip, window_minutes=15)
            security_logger.warning(f"Failed login attempt for IP {client_ip}: {str(e)}")
            
            return Response({
                'error': 'Unable to log in with provided credentials.'
            }, status=status.HTTP_401_UNAUTHORIZED)


class SuperAdminLoginView(APIView):
    """
    Step 1 of Super Admin login.
    Takes email and password, and if valid for a super admin,
    sends an OTP to their email.
    """
    permission_classes = []
    throttle_classes = [OTPRateThrottle]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")
        client_ip = get_client_ip(request)

        # Check rate limiting
        allowed, message = check_rate_limit(f"superadmin_{client_ip}", max_attempts=3, window_minutes=30)
        if not allowed:
            security_logger.warning(f"Super admin login rate limit exceeded for IP {client_ip}")
            return Response({'error': message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        user = authenticate(request=request, email=email, password=password)

        if not user or not user.is_superuser or not user.role or user.role.name != 'Super Admin':
            record_attempt(f"superadmin_{client_ip}", window_minutes=30)
            security_logger.warning(f"Invalid super admin login attempt from IP {client_ip} for email {email}")
            return Response(
                {"error": "Invalid credentials or not a Super Admin."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Generate and send secure OTP
        otp = generate_secure_otp(length=8)
        store_otp_securely(user.email, otp, timeout=300)  # 5 minutes

        # Send OTP to the user's email
        try:
            send_mail(
                subject="Your Admin Login OTP - PRS System",
                message=f"Your One-Time Password is: {otp}\n\nThis OTP is valid for 5 minutes.\n\nIf you did not request this, please contact your system administrator immediately.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            
            security_logger.info(f"OTP sent to super admin {user.email} from IP {client_ip}")
            
            return Response(
                {"message": "An OTP has been sent to the designated admin email. It is valid for 5 minutes."},
                status=status.HTTP_200_OK,
            )
            
        except Exception as e:
            security_logger.error(f"Failed to send OTP to {user.email}: {str(e)}")
            return Response(
                {"error": "Failed to send OTP. Please try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class SuperAdminVerifyOTPView(APIView):
    """
    Step 2 of Super Admin login.
    Takes email and OTP, and if valid, returns the auth token.
    """
    permission_classes = []
    throttle_classes = [OTPRateThrottle]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        otp = request.data.get("otp")
        client_ip = get_client_ip(request)

        if not email or not otp:
            return Response(
                {"error": "Email and OTP are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify OTP securely
        valid, message = verify_otp_securely(email, otp)
        
        if not valid:
            security_logger.warning(f"OTP verification failed for {email} from IP {client_ip}: {message}")
            return Response(
                {"error": message},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            security_logger.warning(f"OTP verification attempted for non-existent user {email} from IP {client_ip}")
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        token, _ = Token.objects.get_or_create(user=user)
        _create_user_session(request, user, token)

        security_logger.info(f"Successful super admin login for {user.email} from IP {client_ip}")

        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email,
            'role': user.role.name if user.role else None
        })


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


class LogoutView(APIView):
    """
    An endpoint for logging out a user.
    This revokes the user's authentication token and server-side session.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def post(self, request, *args, **kwargs):
        # Delete the token to invalidate it
        try:
            request.user.auth_token.delete()
        except (AttributeError, Token.DoesNotExist):
            pass  # The user might not have a token

        # Delete the server-side session record
        UserSession.objects.filter(user=request.user).delete()
        
        security_logger.info(f"User {request.user.email} logged out from IP {get_client_ip(request)}")

        return Response(
            {"message": "Successfully logged out."},
            status=status.HTTP_200_OK
        )