#!/usr/bin/env python
"""
Simple WebSocket test without database operations
"""
import asyncio
import websockets
import json

async def test_websocket_connection():
    """Test WebSocket connection with a known token"""
    # Use the token from your logs: 27365942f3cf43027e9fc458f041469706986b1c
    token = "27365942f3cf43027e9fc458f041469706986b1c"
    
    paths = [
        f"ws://localhost:8000/ws/?token={token}",
        f"ws://localhost:8000/ws/notifications/?token={token}"
    ]
    
    for path in paths:
        print(f"\n🔌 Testing: {path}")
        try:
            async with websockets.connect(path) as websocket:
                print("✅ Connected successfully!")
                
                # Wait for any initial message
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                    data = json.loads(response)
                    print(f"📨 Received: {data}")
                except asyncio.TimeoutError:
                    print("⏰ No initial message received")
                except json.JSONDecodeError as e:
                    print(f"📨 Received non-JSON: {response}")
                
                # Send ping
                ping_msg = json.dumps({"type": "ping"})
                await websocket.send(ping_msg)
                print(f"📤 Sent: {ping_msg}")
                
                # Wait for response
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                    print(f"📨 Response: {response}")
                except asyncio.TimeoutError:
                    print("⏰ No response received")
                    
        except websockets.exceptions.InvalidStatusCode as e:
            print(f"❌ HTTP Error: {e}")
        except ConnectionRefusedError:
            print("❌ Connection refused - is the server running?")
        except Exception as e:
            print(f"❌ Connection failed: {e}")

if __name__ == '__main__':
    print("🚀 Simple WebSocket Test")
    asyncio.run(test_websocket_connection())