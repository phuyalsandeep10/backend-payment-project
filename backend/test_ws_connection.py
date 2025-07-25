#!/usr/bin/env python
"""
Test WebSocket connection with both paths
"""
import asyncio
import websockets
import json
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

User = get_user_model()

async def test_websocket_paths():
    """Test both WebSocket paths"""
    # Get test user and token
    user, created = User.objects.get_or_create(
        email='test@example.com',
        defaults={'username': 'testuser', 'is_active': True}
    )
    token, created = Token.objects.get_or_create(user=user)
    
    # Test both paths
    paths = [
        f"ws://localhost:8000/ws/?token={token.key}",
        f"ws://localhost:8000/ws/notifications/?token={token.key}"
    ]
    
    for path in paths:
        print(f"\n🔌 Testing: {path}")
        try:
            async with websockets.connect(path) as websocket:
                print("✅ Connected successfully!")
                
                # Wait for welcome message
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                    data = json.loads(response)
                    print(f"📨 Received: {data}")
                except asyncio.TimeoutError:
                    print("⏰ No welcome message received")
                
                # Send ping
                await websocket.send(json.dumps({"type": "ping"}))
                print("📤 Sent ping")
                
                # Wait for pong
                try:
                    pong = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                    pong_data = json.loads(pong)
                    print(f"📨 Received: {pong_data}")
                except asyncio.TimeoutError:
                    print("⏰ No pong received")
                    
        except Exception as e:
            print(f"❌ Connection failed: {e}")

if __name__ == '__main__':
    print("🚀 Testing WebSocket Connections")
    asyncio.run(test_websocket_paths())