#!/usr/bin/env python
"""
Comprehensive test script for real-time notification system
"""
import os
import sys
import django
import asyncio
import websockets
import json
from datetime import datetime
from asgiref.sync import sync_to_async

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from notifications.services import NotificationService

User = get_user_model()

@sync_to_async
def get_test_user():
    """Get test user synchronously"""
    return User.objects.filter(email='salesperson@gmail.com').first()

@sync_to_async
def get_or_create_token(user):
    """Get or create token synchronously"""
    token, created = Token.objects.get_or_create(user=user)
    return token

@sync_to_async
def create_test_notification(user):
    """Create test notification synchronously"""
    return NotificationService.create_notification(
        recipient=user,
        notification_type='system_alert',
        title='WebSocket Test',
        message=f'Test notification at {datetime.now()}',
        priority='high'
    )

async def test_websocket_connection():
    """Test WebSocket connection and real-time notifications"""
    print("🔌 Testing WebSocket Connection...")
    
    # Get test user
    user = await get_test_user()
    if not user:
        print("❌ Test user not found")
        return False
    
    # Get token
    token = await get_or_create_token(user)
    
    try:
        uri = f"ws://localhost:8000/ws/notifications/?token={token.key}"
        async with websockets.connect(uri) as websocket:
            print("✅ WebSocket connected successfully")
            
            # Wait for connection confirmation
            response = await websocket.recv()
            data = json.loads(response)
            print(f"📨 Connection response: {data.get('message')}")
            print(f"👥 User groups: {data.get('groups', [])}")
            
            # Wait for notification batch
            batch_response = await websocket.recv()
            batch_data = json.loads(batch_response)
            print(f"📦 Notification batch: {batch_data.get('count', 0)} notifications")
            
            # Test heartbeat
            print("💓 Testing heartbeat...")
            await websocket.send(json.dumps({"type": "ping"}))
            pong = await websocket.recv()
            pong_data = json.loads(pong)
            if pong_data.get('type') == 'pong':
                print("✅ Heartbeat working")
            else:
                print(f"❌ Expected pong, got: {pong_data}")
            
            # Create test notification
            print("📤 Creating test notification...")
            notification = await create_test_notification(user)
            
            # Wait for notification
            try:
                print("⏳ Waiting for real-time notification...")
                notification_msg = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                notif_data = json.loads(notification_msg)
                if notif_data.get('type') == 'notification':
                    print("✅ Real-time notification received")
                    print(f"📨 Notification: {notif_data['notification']['title']}")
                    print(f"🔔 Priority: {notif_data['notification'].get('priority', 'N/A')}")
                else:
                    print(f"❌ Unexpected message type: {notif_data.get('type')}")
                    print(f"📨 Full message: {notif_data}")
            except asyncio.TimeoutError:
                print("❌ No notification received within 5 seconds")
                return False
                
    except Exception as e:
        print(f"❌ WebSocket connection failed: {e}")
        return False
    
    return True

if __name__ == '__main__':
    print("🚀 Starting Real-time Notification System Tests\n")
    
    try:
        result = asyncio.run(test_websocket_connection())
        if result:
            print("\n🎉 All tests passed! Real-time notifications are working!")
        else:
            print("\n❌ Some tests failed.")
    except KeyboardInterrupt:
        print("\n⏹️ Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
    
    print("\n🏁 Tests completed")
