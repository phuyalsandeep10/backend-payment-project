#!/usr/bin/env python
"""
Debug ASGI configuration
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.conf import settings

def check_asgi_setup():
    """Check ASGI configuration"""
    print("🔍 Checking ASGI Setup...")
    
    # Check ASGI_APPLICATION setting
    asgi_app = getattr(settings, 'ASGI_APPLICATION', None)
    print(f"ASGI_APPLICATION: {asgi_app}")
    
    # Check if channels is in INSTALLED_APPS
    installed_apps = getattr(settings, 'INSTALLED_APPS', [])
    if 'channels' in installed_apps:
        print("✅ Channels is in INSTALLED_APPS")
    else:
        print("❌ Channels is NOT in INSTALLED_APPS")
    
    # Check CHANNEL_LAYERS
    channel_layers = getattr(settings, 'CHANNEL_LAYERS', None)
    if channel_layers:
        print("✅ CHANNEL_LAYERS configured")
        print(f"Backend: {channel_layers.get('default', {}).get('BACKEND')}")
    else:
        print("❌ CHANNEL_LAYERS not configured")
    
    # Try to import ASGI application
    try:
        from core_config.asgi import application
        print("✅ ASGI application imported successfully")
        print(f"Application type: {type(application)}")
        
        # Check if it's a ProtocolTypeRouter
        if hasattr(application, 'application_mapping'):
            print("✅ ProtocolTypeRouter detected")
            websocket_app = application.application_mapping.get('websocket')
            print(f"WebSocket application: {websocket_app}")
        else:
            print("❌ Not a ProtocolTypeRouter")
            
    except Exception as e:
        print(f"❌ Error importing ASGI application: {e}")

if __name__ == '__main__':
    check_asgi_setup()