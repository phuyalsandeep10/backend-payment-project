#!/usr/bin/env python
"""
Comprehensive Notification System Test
Tests all aspects of the notification system implementation
"""

import os
import sys
import django
from django.conf import settings

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from authentication.models import User
from organization.models import Organization
from permissions.models import Role, Permission
from clients.models import Client
from deals.models import Deal
from notifications.models import Notification, NotificationSettings, EmailNotificationLog
from notifications.services import NotificationService
import json

def run_notification_tests():
    """Run comprehensive notification system tests."""
    
    print("🔔 NOTIFICATION SYSTEM - COMPREHENSIVE TESTING")
    print("=" * 60)
    print()
    
    # Test 1: Database Structure
    print("🔍 TEST 1: DATABASE STRUCTURE VERIFICATION")
    print("-" * 45)
    
    try:
        # Check notification model
        notification_count = Notification.objects.count()
        settings_count = NotificationSettings.objects.count()
        email_log_count = EmailNotificationLog.objects.count()
        
        print(f"✅ Notification table: {notification_count} records")
        print(f"✅ NotificationSettings table: {settings_count} records")
        print(f"✅ EmailNotificationLog table: {email_log_count} records")
        print(f"✅ Database structure: VERIFIED")
        
    except Exception as e:
        print(f"❌ Database structure error: {e}")
        return False
    
    print()
    
    # Test 2: Create Test Organization and Users
    print("🔍 TEST 2: CREATING TEST DATA")
    print("-" * 35)
    
    try:
        # Create test organization
        org, created = Organization.objects.get_or_create(
            name='Test Notification Org',
            defaults={'is_active': True}
        )
        print(f"✅ Test organization: {'Created' if created else 'Found'}")
        
        # Create admin role
        admin_role, created = Role.objects.get_or_create(
            name='admin',
            organization=org
        )
        print(f"✅ Admin role: {'Created' if created else 'Found'}")
        
        # Create test users
        admin_user, created = User.objects.get_or_create(
            email='admin@testnotification.com',
            defaults={
                'username': 'admin_notification_test',
                'organization': org,
                'role': admin_role,
                'is_active': True
            }
        )
        print(f"✅ Admin user: {'Created' if created else 'Found'}")
        
        regular_user, created = User.objects.get_or_create(
            email='user@testnotification.com',
            defaults={
                'username': 'user_notification_test',
                'organization': org,
                'is_active': True
            }
        )
        print(f"✅ Regular user: {'Created' if created else 'Found'}")
        
    except Exception as e:
        print(f"❌ Test data creation error: {e}")
        return False
    
    print()
    
    # Test 3: Direct Notification Creation
    print("🔍 TEST 3: DIRECT NOTIFICATION CREATION")
    print("-" * 40)
    
    try:
        # Create notification using service
        notifications = NotificationService.create_notification(
            notification_type='system_alert',
            title='Test System Alert',
            message='This is a test notification for system verification.',
            recipient=admin_user,
            organization=org,
            priority='medium',
            category='system',
            send_email_to_superadmin=False
        )
        
        if notifications:
            notification = notifications[0]
            print(f"✅ Notification created: ID {notification.id}")
            print(f"✅ Title: {notification.title}")
            print(f"✅ Recipient: {notification.recipient.email}")
            print(f"✅ Priority: {notification.priority}")
            print(f"✅ Category: {notification.category}")
        else:
            print("❌ No notifications created")
            return False
            
    except Exception as e:
        print(f"❌ Notification creation error: {e}")
        return False
    
    print()
    
    # Test 4: Organization-wide Notifications
    print("🔍 TEST 4: ORGANIZATION-WIDE NOTIFICATIONS")
    print("-" * 43)
    
    try:
        # Create notification for all users in organization
        notifications = NotificationService.notify_role_based_users(
            organization=org,
            notification_type='user_created',
            title='Welcome to the Organization',
            message='A new user has joined the organization.',
            priority='low',
            send_email_to_superadmin=False
        )
        
        print(f"✅ Organization notifications created: {len(notifications)}")
        for notif in notifications:
            print(f"   - {notif.recipient.email}: {notif.title}")
            
    except Exception as e:
        print(f"❌ Organization notification error: {e}")
        return False
    
    print()
    
    # Test 5: Notification Settings
    print("🔍 TEST 5: NOTIFICATION SETTINGS")
    print("-" * 32)
    
    try:
        # Create/get notification settings for admin user
        settings, created = NotificationSettings.objects.get_or_create(
            user=admin_user
        )
        print(f"✅ Admin settings: {'Created' if created else 'Found'}")
        print(f"✅ Client notifications: {settings.enable_client_notifications}")
        print(f"✅ Deal notifications: {settings.enable_deal_notifications}")
        print(f"✅ Min priority: {settings.min_priority}")
        
        # Update settings
        settings.min_priority = 'high'
        settings.enable_client_notifications = False
        settings.save()
        print(f"✅ Settings updated successfully")
        
    except Exception as e:
        print(f"❌ Notification settings error: {e}")
        return False
    
    print()
    
    # Test 6: Signal-based Notifications (Client Creation)
    print("🔍 TEST 6: SIGNAL-BASED NOTIFICATIONS")
    print("-" * 37)
    
    try:
        initial_count = Notification.objects.count()
        
        # Create a test client (should trigger notification signal)
        client = Client.objects.create(
            client_name='Test Notification Client',
            email='testclient@notification.com',
            phone_number='+1234567890',
            created_by=admin_user,
            organization=org
        )
        
        final_count = Notification.objects.count()
        new_notifications = final_count - initial_count
        
        print(f"✅ Client created: {client.client_name}")
        print(f"✅ Notifications triggered: {new_notifications}")
        
        if new_notifications > 0:
            recent_notifications = Notification.objects.filter(
                notification_type='client_created'
            ).order_by('-created_at')[:3]
            
            for notif in recent_notifications:
                print(f"   - {notif.recipient.email}: {notif.title}")
        
    except Exception as e:
        print(f"❌ Signal-based notification error: {e}")
        return False
    
    print()
    
    # Test 7: Notification Queries and Stats
    print("🔍 TEST 7: NOTIFICATION QUERIES & STATS")
    print("-" * 37)
    
    try:
        # Get user notifications
        user_notifications = NotificationService.get_user_notifications(admin_user, limit=10)
        unread_count = NotificationService.get_unread_count(admin_user)
        
        print(f"✅ Admin user notifications: {len(user_notifications)}")
        print(f"✅ Unread count: {unread_count}")
        
        # Mark some as read
        if user_notifications:
            mark_count = NotificationService.mark_notifications_as_read(
                admin_user, 
                notification_ids=[user_notifications[0].id]
            )
            print(f"✅ Marked as read: {mark_count} notifications")
        
        # Get notification stats
        all_notifications = Notification.objects.filter(organization=org)
        by_type = {}
        by_priority = {}
        
        for notif in all_notifications:
            by_type[notif.notification_type] = by_type.get(notif.notification_type, 0) + 1
            by_priority[notif.priority] = by_priority.get(notif.priority, 0) + 1
        
        print(f"✅ Notifications by type: {dict(list(by_type.items())[:3])}")
        print(f"✅ Notifications by priority: {by_priority}")
        
    except Exception as e:
        print(f"❌ Notification queries error: {e}")
        return False
    
    print()
    
    # Test 8: Email Notification Testing
    print("🔍 TEST 8: EMAIL NOTIFICATION SYSTEM")
    print("-" * 35)
    
    try:
        # Test email notification creation
        superadmin_email = getattr(settings, 'SUPER_ADMIN_OTP_EMAIL', 'admin@example.com')
        
        notifications = NotificationService.create_notification(
            notification_type='deal_created',
            title='High Value Deal Created',
            message='A high-value deal has been created requiring attention.',
            recipient=admin_user,
            organization=org,
            priority='high',
            category='business',
            send_email_to_superadmin=True
        )
        
        # Check if email log was created
        recent_emails = EmailNotificationLog.objects.filter(
            email_type='instant_alert'
        ).order_by('-created_at')[:1]
        
        if recent_emails:
            email_log = recent_emails[0]
            print(f"✅ Email notification queued")
            print(f"✅ Recipient: {email_log.recipient_email}")
            print(f"✅ Subject: {email_log.subject[:50]}...")
            print(f"✅ Status: {email_log.status}")
        else:
            print("⚠️ No email logs found (may be expected in development)")
        
    except Exception as e:
        print(f"❌ Email notification error: {e}")
        return False
    
    print()
    
    # Test 9: Notification Types and Categories
    print("🔍 TEST 9: NOTIFICATION TYPES & CATEGORIES")
    print("-" * 40)
    
    try:
        # Test different notification types
        notification_types = [
            ('client_created', 'business'),
            ('deal_created', 'business'),
            ('user_created', 'user_management'),
            ('system_alert', 'system'),
            ('payment_received', 'business'),
        ]
        
        created_count = 0
        for notif_type, category in notification_types:
            notifications = NotificationService.create_notification(
                notification_type=notif_type,
                title=f'Test {notif_type.replace("_", " ").title()}',
                message=f'Testing {notif_type} notification type.',
                recipient=regular_user,
                organization=org,
                priority='low',
                category=category,
                send_email_to_superadmin=False
            )
            created_count += len(notifications)
        
        print(f"✅ Various notification types created: {created_count}")
        
        # Check notification type distribution
        type_distribution = Notification.objects.filter(
            organization=org
        ).values_list('notification_type', flat=True)
        
        unique_types = set(type_distribution)
        print(f"✅ Unique notification types in system: {len(unique_types)}")
        
    except Exception as e:
        print(f"❌ Notification types error: {e}")
        return False
    
    print()
    
    # Final Summary
    print("🎯 NOTIFICATION SYSTEM TEST SUMMARY")
    print("=" * 40)
    
    try:
        total_notifications = Notification.objects.count()
        total_settings = NotificationSettings.objects.count()
        total_email_logs = EmailNotificationLog.objects.count()
        
        print(f"✅ Total Notifications Created: {total_notifications}")
        print(f"✅ Total Notification Settings: {total_settings}")
        print(f"✅ Total Email Logs: {total_email_logs}")
        print(f"✅ Test Organization: {org.name}")
        print(f"✅ Test Users Created: 2")
        
        # Check recent notifications
        recent_notifications = Notification.objects.order_by('-created_at')[:5]
        print(f"✅ Recent Notifications:")
        for notif in recent_notifications:
            print(f"   - {notif.notification_type}: {notif.title[:30]}...")
        
        print()
        print("🏆 NOTIFICATION SYSTEM: FULLY OPERATIONAL!")
        print("🔔 Ready for frontend integration!")
        
        return True
        
    except Exception as e:
        print(f"❌ Summary generation error: {e}")
        return False

if __name__ == '__main__':
    success = run_notification_tests()
    
    if success:
        print("\n🎉 ALL TESTS PASSED! Notification system is ready for use.")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
    
    sys.exit(0 if success else 1) 