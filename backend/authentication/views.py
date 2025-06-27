from django.contrib.auth import authenticate
from .models import User, UserSession
from .serializers import LoginSerializer, UserSerializer, UserCreateSerializer, UserSessionSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework import status, viewsets
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
import random
from .filters import UserFilter
from organization.permissions import HasPermission


def _create_user_session(request, user, token):
    """
    Helper function to create a UserSession record.
    """
    # Clean up old sessions for the same user to avoid clutter
    # This is optional but good practice. You might want to limit the number of active sessions.
    # UserSession.objects.filter(user=user).delete()

    ip_address = request.META.get('REMOTE_ADDR')
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    UserSession.objects.create(
        user=user,
        session_key=token.key,
        ip_address=ip_address,
        user_agent=user_agent
    )

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all()
    filterset_class = UserFilter

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

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.action == 'create':
            self.permission_classes = [HasPermission('create_user')]
        elif self.action in ['list', 'retrieve']:
            self.permission_classes = [HasPermission('view_user')]
        elif self.action in ['update', 'partial_update']:
            self.permission_classes = [HasPermission('edit_user')]
        elif self.action == 'destroy':
            self.permission_classes = [HasPermission('delete_user')]
        else:
            self.permission_classes = [IsAuthenticated]
        
        return super().get_permissions()

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
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        username = serializer.validated_data.get("username")
        password = serializer.validated_data.get("password")

        user = authenticate(username=username, password=password)

        if user:
            # You can decide here which roles are allowed to log in via this endpoint
            token, _ = Token.objects.get_or_create(user=user)
            _create_user_session(request, user, token)
            user_data = UserSerializer(user).data
            return Response({
                "token": token.key,
                "message": "Login successful",
                "user": user_data
            })
        
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_401_UNAUTHORIZED
        )

class SuperAdminLoginView(APIView):
    """
    Step 1 of Super Admin login.
    Takes username and password, and if valid for a super admin,
    sends an OTP to their email.
    """
    permission_classes = []

    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)

        if not user or user.org_role != User.Role.SUPER_ADMIN:
            return Response(
                {"error": "Invalid credentials or not a Super Admin."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Generate and send OTP
        otp = str(random.randint(100000, 999999))
        cache.set(f"otp_{user.username}", otp, timeout=300)  # OTP valid for 5 minutes

        # Send OTP to the user's email
        recipient_email = user.email
        send_mail(
            subject="Your Admin Login OTP",
            message=f"Your One-Time Password is: {otp}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient_email],
            fail_silently=False,
        )

        return Response(
            {"message": f"An OTP has been sent to the designated admin email. It is valid for 5 minutes."},
            status=status.HTTP_200_OK,
        )


class SuperAdminVerifyOTPView(APIView):
    """
    Step 2 of Super Admin login.
    Takes username and OTP, and if valid, returns the auth token.
    """
    permission_classes = []

    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        otp = request.data.get("otp")

        stored_otp = cache.get(f"otp_{username}")

        if not stored_otp or stored_otp != otp:
            return Response(
                {"error": "Invalid or expired OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.get(username=username)
        token, _ = Token.objects.get_or_create(user=user)
        _create_user_session(request, user, token)

        # Clear the OTP from cache after successful verification
        cache.delete(f"otp_{username}")

        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email,
            'role': user.org_role
        })


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
