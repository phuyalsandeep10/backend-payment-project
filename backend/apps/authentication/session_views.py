"""
Session Management Views

This module contains views for managing user sessions and email testing.
Extracted from views.py for better organization and reduced complexity.
"""

import logging

from django.core import mail
from django.conf import settings

from rest_framework import status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from .models import UserSession
from .serializers import UserSessionSerializer
from .response_validators import validate_response_type

# Security logger
security_logger = logging.getLogger('security')


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
@validate_response_type
def test_email_outbox_view(request):
    """Test view for accessing email outbox in debug mode."""
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
