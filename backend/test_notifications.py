#!/usr/bin/env python
"""
Test script to verify notification endpoints are working.
Run this from the backend directory.
"""

import os
import sys
import django

# Setup Django first
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status

from notifications.models import Notification, NotificationSettings
from notifications.services import NotificationService

User = get_user_model()

def test_notification_endpoints():
    """Test the notification endpoints"""
    print("Testing notification endpoints...")
    
    # Create a test user
    try:
        user = User.objects.get(email='test@example.com')
    except User.DoesNotExist:
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        print(f"Created test user: {user.email}")
    
    # Create notification settings for the user
    settings, created = NotificationSettings.objects.get_or_create(user=user)
    if created:
        print(f"Created notification settings for {user.email}")
    
    # Create some test notifications
    notifications = []
    for i in range(3):
        notification = Notification.objects.create(
            recipient=user,
            title=f'Test Notification {i+1}',
            message=f'This is test notification {i+1}',
            notification_type='system_alert',
            priority='medium',
            category='system',
            is_read=(i == 0)  # First one is read
        )
        notifications.append(notification)
        print(f"Created notification: {notification.title}")
    
    # Test the API endpoints
    client = APIClient()
    client.force_authenticate(user=user)
    
    # Test 1: List notifications
    print("\n1. Testing list notifications endpoint...")
    response = client.get('/api/notifications/')
    if response.status_code == status.HTTP_200_OK:
        # Handle paginated response
        results = response.data.get('results', response.data)
        print(f"✅ List notifications: {len(results)} notifications found")
        for notif in results[:2]:  # Show first 2
            print(f"   - {notif['title']} ({notif['notificationType']})")
    else:
        print(f"❌ List notifications failed: {response.status_code}")
    
    # Test 2: Get unread count
    print("\n2. Testing unread count endpoint...")
    response = client.get('/api/notifications/unread_count/')
    if response.status_code == status.HTTP_200_OK:
        print(f"✅ Unread count: {response.data['unread_count']}")
    else:
        print(f"❌ Unread count failed: {response.status_code}")
    
    # Test 3: Get notification stats
    print("\n3. Testing notification stats endpoint...")
    response = client.get('/api/notifications/stats/')
    if response.status_code == status.HTTP_200_OK:
        print(f"✅ Stats: {response.data['total_notifications']} total, {response.data['unread_count']} unread")
    else:
        print(f"❌ Stats failed: {response.status_code}")
    
    # Test 4: Mark notification as read
    if notifications:
        print("\n4. Testing mark as read endpoint...")
        notification_id = notifications[0].id
        response = client.post(f'/api/notifications/{notification_id}/mark_as_read/')
        if response.status_code == status.HTTP_200_OK:
            print(f"✅ Mark as read: {response.data['message']}")
        else:
            print(f"❌ Mark as read failed: {response.status_code}")
    
    # Test 5: Get notification preferences
    print("\n5. Testing notification preferences endpoint...")
    response = client.get('/api/notifications/preferences/')
    if response.status_code == status.HTTP_200_OK:
        print(f"✅ Preferences: {response.data['enable_system_notifications']}")
    else:
        print(f"❌ Preferences failed: {response.status_code}")
    
    # Test 6: Test service methods
    print("\n6. Testing service methods...")
    unread_count = NotificationService.get_unread_count(user)
    print(f"✅ Service unread count: {unread_count}")
    
    stats = NotificationService.get_user_notification_stats(user)
    print(f"✅ Service stats: {stats['total_notifications']} total, {stats['unread_count']} unread")
    
    print("\n🎉 All tests completed!")
    
    # Cleanup
    print("\nCleaning up test data...")
    for notification in notifications:
        notification.delete()
    print("Test notifications deleted.")

if __name__ == '__main__':
    test_notification_endpoints() 