from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Notification, NotificationSettings, EmailNotificationLog, NotificationTemplate
from .serializers import (
    NotificationSerializer, NotificationSettingsSerializer, 
    EmailNotificationLogSerializer, NotificationTemplateSerializer,
    MarkAsReadSerializer, NotificationStatsSerializer
)
from .services import NotificationService

class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for managing user notifications.
    Provides list, retrieve, and custom actions for notifications.
    """
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Return notifications for the current user."""
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Notification.objects.none()
            
        return Notification.objects.filter(recipient=self.request.user).select_related(
            'recipient', 'organization'
        )
    
    def list(self, request, *args, **kwargs):
        """List notifications with optional filtering."""
        queryset = self.get_queryset()
        
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
        
        # Limit results
        limit = request.query_params.get('limit', '50')
        try:
            limit = int(limit)
            queryset = queryset[:limit]
        except ValueError:
            queryset = queryset[:50]
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def mark_as_read(self, request):
        """Mark notifications as read."""
        serializer = MarkAsReadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        notification_ids = serializer.validated_data.get('notification_ids')
        count = NotificationService.mark_notifications_as_read(
            user=request.user,
            notification_ids=notification_ids
        )
        
        return Response({
            'message': f'{count} notifications marked as read.',
            'count': count
        })
    
    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        """Mark a specific notification as read."""
        notification = get_object_or_404(Notification, pk=pk, recipient=request.user)
        notification.mark_as_read()
        
        return Response({
            'message': 'Notification marked as read.',
            'notification': NotificationSerializer(notification).data
        })
    
    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """Get count of unread notifications."""
        count = NotificationService.get_unread_count(request.user)
        return Response({'unread_count': count})
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get notification statistics for the user."""
        user = request.user
        
        # Get all notifications for user
        notifications = Notification.objects.filter(recipient=user)
        
        # Count by type
        by_type = notifications.values('notification_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Count by priority
        by_priority = notifications.values('priority').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Recent notifications (last 10)
        recent = notifications[:10]
        
        stats_data = {
            'total_notifications': notifications.count(),
            'unread_count': notifications.filter(is_read=False).count(),
            'by_type': {item['notification_type']: item['count'] for item in by_type},
            'by_priority': {item['priority']: item['count'] for item in by_priority},
            'recent_notifications': NotificationSerializer(recent, many=True).data
        }
        
        serializer = NotificationStatsSerializer(stats_data)
        return Response(serializer.data)

class NotificationSettingsViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing user notification settings.
    """
    serializer_class = NotificationSettingsSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Return notification settings for the current user."""
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return NotificationSettings.objects.none()
            
        return NotificationSettings.objects.filter(user=self.request.user)
    
    def get_object(self):
        """Get or create notification settings for the current user."""
        settings, created = NotificationSettings.objects.get_or_create(
            user=self.request.user
        )
        return settings
    
    def list(self, request, *args, **kwargs):
        """Return user's notification settings."""
        settings = self.get_object()
        serializer = self.get_serializer(settings)
        return Response(serializer.data)
    
    def update(self, request, *args, **kwargs):
        """Update user's notification settings."""
        settings = self.get_object()
        serializer = self.get_serializer(settings, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response({
            'message': 'Notification settings updated successfully.',
            'settings': serializer.data
        })

class EmailNotificationLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing email notification logs (admin only).
    """
    serializer_class = EmailNotificationLogSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Return email logs - super admin sees all, org admin sees their org only."""
        # Handle schema generation when user is anonymous
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return EmailNotificationLog.objects.none()
            
        user = self.request.user
        
        if user.is_superuser:
            return EmailNotificationLog.objects.all().select_related('organization')
        elif hasattr(user, 'organization') and user.organization and hasattr(user, 'role') and user.role and 'admin' in user.role.name.lower():
            return EmailNotificationLog.objects.filter(
                organization=user.organization
            ).select_related('organization')
        else:
            # Regular users can't see email logs
            return EmailNotificationLog.objects.none()

class NotificationTemplateViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing notification templates (admin only).
    """
    serializer_class = NotificationTemplateSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Return notification templates for admins only."""
        user = self.request.user
        
        if user.is_superuser or (hasattr(user, 'role') and user.role and 'admin' in user.role.name.lower()):
            return NotificationTemplate.objects.all()
        else:
            return NotificationTemplate.objects.none()
    
    def perform_create(self, serializer):
        """Create notification template."""
        serializer.save()
    
    def perform_update(self, serializer):
        """Update notification template."""
        serializer.save()

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