#!/usr/bin/env python
"""
Quick script to clear rate limiting cache for testing purposes.
"""

import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.core.cache import cache

def clear_rate_limits():
    """Clear all rate limiting cache entries."""
    try:
        # Get all cache keys
        if hasattr(cache, '_cache') and hasattr(cache._cache, 'get_stats'):
            # Redis cache
            cache.clear()
            print("✅ Cleared Redis cache completely")
        else:
            # Try to clear specific rate limit keys
            cache_keys_to_clear = []
            
            # Common rate limit key patterns
            patterns = [
                'rate_limit:127.0.0.1:',
                'rate_limit:localhost:',
                'throttle_',
                'anon_',
                'user_',
            ]
            
            # For local memory cache, we'll just clear everything
            cache.clear()
            print("✅ Cleared local memory cache completely")
            
        print("✅ Rate limits have been cleared!")
        print("📝 You can now try the authentication flow again.")
        
    except Exception as e:
        print(f"❌ Error clearing cache: {e}")
        print("💡 You may need to restart the Django server to clear rate limits.")

if __name__ == '__main__':
    clear_rate_limits()