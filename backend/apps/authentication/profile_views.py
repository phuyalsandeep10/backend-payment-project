"""
User Profile Management Views

This module contains views for managing user profiles and preferences.
Extracted from views.py for better organization and reduced complexity.
"""

import logging
from decimal import Decimal

from rest_framework import status, generics, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

# Import serializers directly to avoid __init__.py conflicts
from .serializers import UserDetailSerializer
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import UserProfile

User = get_user_model()

class ProfileUpdateSerializer(serializers.ModelSerializer):
    """Simple serializer that handles profile picture uploads correctly."""
    profile_picture = serializers.ImageField(required=False, write_only=True)
    phoneNumber = serializers.CharField(source='contact_number', required=False, allow_blank=True)
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'contact_number', 'phoneNumber', 'address', 'profile_picture']
    
    def update(self, instance, validated_data):
        print(f"=== ProfileUpdateSerializer.update called ===")
        print(f"Validated data: {validated_data}")
        
        profile_picture = validated_data.pop('profile_picture', None)
        print(f"Profile picture: {profile_picture}")
        
        # Update user fields
        instance = super().update(instance, validated_data)
        
        # Handle profile picture
        if profile_picture:
            print(f"Updating profile picture: {profile_picture.name}")
            profile, created = UserProfile.objects.get_or_create(user=instance)
            profile.profile_picture = profile_picture
            profile.save()
            print(f"Profile picture saved: {profile.profile_picture.url}")
        
        instance.refresh_from_db()
        return instance
from .response_validators import validate_response_type
from apps.notifications.models import NotificationSettings
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser

# Security logger
security_logger = logging.getLogger('security')


class UserProfileView(generics.RetrieveUpdateAPIView):
    """Handles retrieving and updating the authenticated user's profile."""
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_object(self):
        return self.request.user
    
    def patch(self, request, *args, **kwargs):
        print(f"=== UserProfileView.patch() called ===")
        print(f"Request method: {request.method}")
        print(f"Content type: {request.content_type}")
        print(f"Request data keys: {list(request.data.keys())}")
        print(f"Request FILES keys: {list(request.FILES.keys())}")
        print(f"Has profile_picture in data: {'profile_picture' in request.data}")
        print(f"Has profile_picture in FILES: {'profile_picture' in request.FILES}")
        return super().patch(request, *args, **kwargs)

    def get_serializer_class(self):
        # Handle swagger schema generation
        if getattr(self, 'swagger_fake_view', False):
            return UserDetailSerializer
            
        if self.request.method in ['PUT', 'PATCH']:
            print(f"=== UserProfileView: Using ProfileUpdateSerializer for {self.request.method} ===")
            return ProfileUpdateSerializer
        print(f"=== UserProfileView: Using UserDetailSerializer for {self.request.method} ===")
        return UserDetailSerializer
    
    def perform_update(self, serializer):
        print(f"=== UserProfileView.perform_update called ===")
        print(f"Request data keys: {list(self.request.data.keys())}")
        print(f"Request FILES: {list(self.request.FILES.keys())}")
        print(f"Request content type: {self.request.content_type}")
        print(f"Serializer class: {type(serializer)}")
        print(f"Serializer validated_data keys: {list(serializer.validated_data.keys()) if hasattr(serializer, 'validated_data') else 'No validated_data'}")
        result = super().perform_update(serializer)
        print(f"=== UserProfileView.perform_update completed ===")
        return result


@swagger_auto_schema(
    method='post', 
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT, 
        properties={
            'sales_target': openapi.Schema(type=openapi.TYPE_NUMBER)
        }
    ), 
    responses={200: UserDetailSerializer, 400: "Bad Request"}, 
    tags=['User Profile']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@validate_response_type
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


class UserNotificationPreferencesView(generics.RetrieveUpdateAPIView):
    """Retrieve or update the authenticated user's notification preferences."""
    permission_classes = [IsAuthenticated]

    class OutputSerializer(serializers.ModelSerializer):
        # Frontend camelCase fields
        desktopNotification = serializers.BooleanField(source='desktop_notification')
        unreadNotificationBadge = serializers.BooleanField(source='unread_notification_badge')
        pushNotificationTimeout = serializers.CharField(source='push_notification_timeout')
        communicationEmails = serializers.BooleanField(source='communication_emails')
        announcementsUpdates = serializers.BooleanField(source='announcements_updates')
        allNotificationSounds = serializers.BooleanField(source='all_notification_sounds')
        
        # Legacy backend fields for frontend compatibility
        notification_timeout = serializers.CharField(source='push_notification_timeout')
        enable_email_notifications = serializers.BooleanField(source='communication_emails')
        enable_marketing_emails = serializers.BooleanField(source='announcements_updates')
        enable_sound_notifications = serializers.BooleanField(source='all_notification_sounds')
        
        class Meta:
            model = NotificationSettings
            exclude = [
                'id', 'user', 'created_at', 'updated_at', 
                'desktop_notification', 'unread_notification_badge', 
                'push_notification_timeout', 'communication_emails', 
                'announcements_updates', 'all_notification_sounds'
            ]

    class UpdateSerializer(serializers.ModelSerializer):
        # Frontend camelCase fields (read/write)
        desktopNotification = serializers.BooleanField(source='desktop_notification', required=False)
        unreadNotificationBadge = serializers.BooleanField(source='unread_notification_badge', required=False)
        pushNotificationTimeout = serializers.CharField(source='push_notification_timeout', required=False)
        communicationEmails = serializers.BooleanField(source='communication_emails', required=False)
        announcementsUpdates = serializers.BooleanField(source='announcements_updates', required=False)
        allNotificationSounds = serializers.BooleanField(source='all_notification_sounds', required=False)
        
        # Legacy backend fields for compatibility (write-only, redirect to correct fields)
        notification_timeout = serializers.CharField(source='push_notification_timeout', write_only=True, required=False)
        enable_email_notifications = serializers.BooleanField(source='communication_emails', write_only=True, required=False)
        enable_marketing_emails = serializers.BooleanField(source='announcements_updates', write_only=True, required=False)
        enable_sound_notifications = serializers.BooleanField(source='all_notification_sounds', write_only=True, required=False)
        
        class Meta:
            model = NotificationSettings
            fields = [
                'enable_client_notifications', 'enable_deal_notifications', 
                'enable_user_management_notifications', 'enable_team_notifications', 
                'enable_project_notifications', 'enable_commission_notifications', 
                'enable_system_notifications', 'min_priority', 'auto_mark_read_days', 
                'desktopNotification', 'unreadNotificationBadge', 'pushNotificationTimeout', 
                'communicationEmails', 'announcementsUpdates', 'allNotificationSounds',
                'notification_timeout', 'enable_email_notifications', 'enable_marketing_emails', 'enable_sound_notifications'
            ]

    def get_serializer_class(self):
        # Handle swagger schema generation
        if getattr(self, 'swagger_fake_view', False):
            return self.OutputSerializer
            
        if self.request.method in ['PUT', 'PATCH']:
            return self.UpdateSerializer
        return self.OutputSerializer

    def get_object(self):
        settings_obj, _ = NotificationSettings.objects.get_or_create(user=self.request.user)
        return settings_obj


@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([IsAuthenticated])
def test_upload_view(request):
    """Simple test endpoint for file upload debugging."""
    print(f"=== TEST UPLOAD VIEW CALLED ===")
    print(f"Request method: {request.method}")
    print(f"Content type: {request.content_type}")
    print(f"Request data keys: {list(request.data.keys())}")
    print(f"Request files keys: {list(request.FILES.keys())}")
    
    if 'profile_picture' in request.FILES:
        file = request.FILES['profile_picture']
        print(f"File received: {file.name} ({file.size} bytes)")
        
        # Try to save to user profile
        user = request.user
        from .models import UserProfile
        profile, created = UserProfile.objects.get_or_create(user=user)
        print(f"Profile object: {profile}, created: {created}")
            
        profile.profile_picture = file
        profile.save()
        
        print(f"File saved to profile: {profile.profile_picture}")
        return Response({"success": True, "file_url": profile.profile_picture.url if profile.profile_picture else None})
    else:
        print("No profile_picture in request.FILES")
        return Response({"error": "No file provided"}, status=400)
