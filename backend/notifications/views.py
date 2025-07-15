from rest_framework import viewsets, status, permissions, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Notification, NotificationSettings, NotificationTemplate
from .serializers import (
    NotificationSerializer, NotificationSettingsSerializer, 
    NotificationTemplateSerializer,
    MarkAsReadSerializer, NotificationStatsSerializer
)
from .services import NotificationService

@swagger_auto_schema(tags=['Notifications'])
class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for managing user notifications.
    Provides endpoints for listing, retrieving, and managing notifications.
    """
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return Notification.objects.none()
        return Notification.objects.filter(recipient=self.request.user)
    
    def list(self, request, *args, **kwargs):
        """List notifications with optional filtering."""
        queryset = self.get_queryset()

        # DEBUG: Print current user and queryset SQL
        import logging
        logger = logging.getLogger("notifications.debug")
        logger.warning(f"[DEBUG] request.user: id={request.user.id}, email={request.user.email}")
        logger.warning(f"[DEBUG] queryset SQL: {str(queryset.query)}")
        logger.warning(f"[DEBUG] queryset count: {queryset.count()}")

        # Filter by read status
        unread_only = request.query_params.get('unread_only', 'false').lower() == 'true'
        if unread_only:
            queryset = queryset.filter(is_read=False)
        
        # Filter by type
        notification_type = request.query_params.get('type')
        if notification_type:
            queryset = queryset.filter(notification_type=notification_type)
        
        # Filter by priority
        priority = request.query_params.get('priority')
        if priority:
            queryset = queryset.filter(priority=priority)
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'], serializer_class=MarkAsReadSerializer)
    def mark_all_as_read(self, request):
        """Mark multiple notifications as read for the current user."""
        notification_ids = request.data.get('notification_ids', [])
        count = NotificationService.mark_notifications_as_read(user=request.user, notification_ids=notification_ids)
        return Response({'message': f'{count} notifications marked as read.', 'count': count})
    
    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None):
        """Mark a single notification as read."""
        notification = self.get_object()
        notification.mark_as_read()
        return Response({'message': 'Notification marked as read.'})
    
    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """Get the count of unread notifications for the current user."""
        count = NotificationService.get_unread_count(request.user)
        return Response({'unread_count': count})
    
    @action(detail=False, methods=['get'], serializer_class=NotificationStatsSerializer)
    def stats(self, request):
        """Get notification statistics for the current user."""
        stats_data = NotificationService.get_user_notification_stats(request.user)
        return Response(stats_data)

@swagger_auto_schema(tags=['Notifications'])
class NotificationSettingsViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing a user's notification settings.
    """
    serializer_class = NotificationSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # This queryset is used for permission checks and for the browsable API.
        # The actual object is fetched based on the current user.
        if getattr(self, 'swagger_fake_view', False):
            return NotificationSettings.objects.none()
        return NotificationSettings.objects.filter(user=self.request.user)

    def get_object(self):
        # Overriding get_object to ensure users can only access their own settings.
        # get_or_create ensures a settings object exists for every user.
        settings, _ = NotificationSettings.objects.get_or_create(user=self.request.user)
        return settings

    def list(self, request, *args, **kwargs):
        """
        Get the current user's notification settings. 
        There's only one settings object per user, so this returns a single object, not a list.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        """
        Update the current user's notification settings.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        """
        Update the current user's notification settings (full update).
        """
        return self.partial_update(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """
        Creating settings is handled automatically by get_object, so this is disabled.
        """
        return Response(
            {'detail': 'Method "POST" not allowed.'}, 
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )

class NotificationPreferencesView(generics.RetrieveUpdateAPIView):
    """
    Get or update notification preferences for the current user.
    """
    serializer_class = NotificationSettingsSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        # get_or_create ensures we always have a settings object for the user
        settings, _ = NotificationSettings.objects.get_or_create(user=self.request.user)
        return settings

@swagger_auto_schema(tags=['Notifications'])
class NotificationAdminViewSet(viewsets.GenericViewSet):
    """
    Admin ViewSet for managing notification templates, logs, and testing.
    Requires admin privileges.
    """
    permission_classes = [IsAdminUser]
    serializer_class = NotificationTemplateSerializer  # Default serializer
    queryset = NotificationTemplate.objects.none()  # Required for schema generation

    @action(detail=False, methods=['get'], serializer_class=NotificationTemplateSerializer)
    def list_templates(self, request):
        """List all notification templates."""
        queryset = NotificationTemplate.objects.all()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'], serializer_class=NotificationTemplateSerializer)
    def create_template(self, request):
        """Create a new notification template."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'])
    def send_test_notification(self, request):
        """Send a test notification to the current admin user."""
        NotificationService.create_notification(
            recipient=request.user,
            notification_type='system_alert',
            title='Admin Test Notification',
            message='This is a test notification sent from the admin panel.'
        )
        return Response({'message': 'Test notification sent successfully.'})

# Additional utility views
from rest_framework.views import APIView

class NotificationDashboardView(APIView):
    """
    Dashboard view for notification system overview.
    """
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get notification system dashboard with statistics and recent activity",
        responses={
            200: openapi.Response(
                description="Dashboard data",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'total_notifications': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'unread_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'recent_notifications': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT)),
                        'system_health': openapi.Schema(type=openapi.TYPE_OBJECT),
                    }
                )
            ),
            401: "Unauthorized"
        },
        tags=['Notifications']
    )
    def get(self, request):
        """Get comprehensive notification dashboard data."""
        user = request.user
        
        # User's notification summary
        user_notifications = Notification.objects.filter(recipient=user)
        unread_count = user_notifications.filter(is_read=False).count()
        recent_notifications = user_notifications[:5]
        
        # Organization summary (if user has access)
        org_data = None
        if user.organization and hasattr(user, 'role') and user.role:
            if 'admin' in user.role.name.lower() or 'manager' in user.role.name.lower():
                org_notifications = Notification.objects.filter(organization=user.organization)
                org_data = {
                    'total_notifications': org_notifications.count(),
                    'today_count': org_notifications.filter(
                        created_at__date=timezone.now().date()
                    ).count(),
                    'by_type': list(org_notifications.values('notification_type').annotate(
                        count=Count('id')
                    ).order_by('-count')[:5])
                }
        
        dashboard_data = {
            'user_summary': {
                'total_notifications': user_notifications.count(),
                'unread_count': unread_count,
                'recent_notifications': NotificationSerializer(recent_notifications, many=True).data
            },
            'organization_summary': org_data,
            'notification_types': dict(Notification.TYPE_CHOICES),
            'priority_levels': dict(Notification.PRIORITY_CHOICES)
        }
        
        return Response(dashboard_data)

class TestNotificationView(APIView):
    """
    View for testing notification system (admin only).
    """
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Send test notification to verify system functionality (admin only)",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'message': openapi.Schema(type=openapi.TYPE_STRING, description="Test message content"),
                'recipient_email': openapi.Schema(type=openapi.TYPE_STRING, description="Email to send test to"),
                'notification_type': openapi.Schema(type=openapi.TYPE_STRING, description="Type of notification to test"),
            },
            required=['message']
        ),
        responses={
            200: openapi.Response(description="Test notification sent successfully"),
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden"
        },
        tags=['Notifications']
    )
    def post(self, request):
        """Create a test notification."""
        user = request.user
        
        # Only allow admins or superusers to create test notifications
        if not (user.is_superuser or (hasattr(user, 'role') and user.role and 'admin' in user.role.name.lower())):
            return Response(
                {'error': 'Permission denied. Only admins can create test notifications.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Create test notification
        notifications = NotificationService.create_notification(
            notification_type='system_alert',
            title='Test Notification',
            message=f'This is a test notification created by {user.get_full_name() or user.email}.',
            recipient=user,
            organization=user.organization,
            priority='low',
            category='system',
            send_email_to_superadmin=False
        )
        
        return Response({
            'message': 'Test notification created successfully.',
            'notification': NotificationSerializer(notifications[0]).data if notifications else None
        }) 