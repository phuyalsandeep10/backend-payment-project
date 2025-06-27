from django.contrib.auth import authenticate
from .models import User
from .serializers import LoginSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
import random

class CustomAuthToken(ObtainAuthToken):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email,
            'role': user.role
        })

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
            return Response({
                "token": token.key,
                "message": "Login successful",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role
                }
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

        if not user or user.role != User.Role.SUPER_ADMIN:
            return Response(
                {"error": "Invalid credentials or not a Super Admin."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Generate and send OTP
        otp = str(random.randint(100000, 999999))
        cache.set(f"otp_{user.username}", otp, timeout=300)  # OTP valid for 5 minutes

        # Send OTP to the secure, predefined email from settings
        recipient_email = settings.SUPER_ADMIN_OTP_EMAIL
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

        # Clear the OTP from cache after successful verification
        cache.delete(f"otp_{username}")

        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email,
            'role': user.role
        })
