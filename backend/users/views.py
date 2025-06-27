from rest_framework import generics, permissions,status
from .models import CustomUser,LoginSession
from rest_framework.views import APIView
from .serializers import UserSerializer,UserRegistrationSerializer,LoginSessionSerializer
from rest_framework.response import Response
from django.contrib.sessions.models import Session

class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]


class UserListCreateView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]
    
      # Only admin can list/create users

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]
    
     # Adjust as needed
     
     
     
    """
    for session revoke and get
    """
    
class UserSessionsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """
        List all sessions for the current user.
        """
        sessions = LoginSession.objects.filter(user=request.user)
        serializer = LoginSessionSerializer(sessions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request):
        """
        Revoke a user session given its session_key.
        Expects JSON payload: { "session_key": "the_session_key" }
        """
        session_key = request.data.get("session_key")
        if not session_key:
            return Response({"detail": "session_key is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the session belongs to the user
        try:
            login_session = LoginSession.objects.get(session_key=session_key, user=request.user)
        except LoginSession.DoesNotExist:
            return Response({"detail": "Session not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)

        # Optional: Protect current session from being deleted.
        if request.session.session_key == session_key:
            return Response({"detail": "You cannot revoke your current session."}, status=status.HTTP_400_BAD_REQUEST)

        # Delete the session from Django's session storage
        Session.objects.filter(session_key=session_key).delete()

        # Remove the record from your LoginSession model
        login_session.delete()

        return Response({"detail": "Session revoked successfully."}, status=status.HTTP_200_OK)