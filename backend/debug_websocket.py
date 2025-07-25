#!/usr/bin/env python
"""
Debug WebSocket connections
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.urls import resolve
from django.conf import settings

def check_websocket_routing():
    """Check WebSocket URL routing"""
    print("🔍 Checking WebSocket routing...")
    
    # Check ASGI application
    print(f"ASGI_APPLICATION: {getattr(settings, 'ASGI_APPLICATION', 'Not set')}")
    
    # Try to import the ASGI application
    try:
        from core_config.asgi import application
        print("✅ ASGI application imported successfully")
        
        # Check if it has websocket routing
        if hasattr(application, 'application_mapping'):
            websocket_app = application.application_mapping.get('websocket')
            print(f"WebSocket app: {websocket_app}")
        
    except Exception as e:
        print(f"❌ Error importing ASGI application: {e}")

if __name__ == '__main__':
    check_websocket_routing()