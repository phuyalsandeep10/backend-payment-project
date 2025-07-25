#!/usr/bin/env python
"""
Check if WebSocket setup is ready
"""
import os
import sys
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

def check_redis():
    """Check Redis connection"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        print("✅ Redis is running")
        return True
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        return False

def check_channels():
    """Check if Channels is installed"""
    try:
        import channels
        print(f"✅ Channels installed: {channels.__version__}")
        return True
    except ImportError:
        print("❌ Channels not installed")
        return False

def check_asgi_config():
    """Check ASGI configuration"""
    try:
        from django.conf import settings
        asgi_app = getattr(settings, 'ASGI_APPLICATION', None)
        if asgi_app:
            print(f"✅ ASGI application configured: {asgi_app}")
            return True
        else:
            print("❌ ASGI_APPLICATION not configured")
            return False
    except Exception as e:
        print(f"❌ ASGI configuration error: {e}")
        return False

def check_channel_layers():
    """Check Channel Layers configuration"""
    try:
        from django.conf import settings
        channel_layers = getattr(settings, 'CHANNEL_LAYERS', None)
        if channel_layers:
            print("✅ Channel Layers configured")
            return True
        else:
            print("❌ CHANNEL_LAYERS not configured")
            return False
    except Exception as e:
        print(f"❌ Channel Layers error: {e}")
        return False

if __name__ == '__main__':
    print("🔍 Checking WebSocket setup...\n")
    
    checks = [
        check_redis(),
        check_channels(),
        check_asgi_config(),
        check_channel_layers()
    ]
    
    if all(checks):
        print("\n🎉 All checks passed! WebSocket server is ready to run.")
        print("\nRun with: python manage.py runserver")
    else:
        print("\n❌ Some checks failed. Please fix the issues above.")