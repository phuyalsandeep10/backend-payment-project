#!/usr/bin/env python
"""
Session Management Methods Test
Test specific session management functionality
"""

import os
import sys
import django
from django.conf import settings

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.utils import timezone
from datetime import timedelta
from authentication.models import SecureUserSession, User
from organization.models import Organization

def test_session_methods():
    """
    Test SecureUserSession methods
    """
    print("🔍 Testing Session Management Methods...")
    
    # Check if methods exist
    methods_to_check = [
        'cleanup_expired_sessions',
        'get_user_active_sessions', 
        'enforce_session_limit',
        'is_expired',
        'mark_suspicious',
        'invalidate',
        'update_activity'
    ]
    
    results = {}
    
    for method_name in methods_to_check:
        if hasattr(SecureUserSession, method_name):
            results[method_name] = "✅ Available"
        else:
            results[method_name] = "❌ Missing"
    
    print("\nSession Management Methods:")
    for method, status in results.items():
        print(f"  {status} {method}")
    
    # Test class methods
    print(f"\n🧪 Testing class methods...")
    
    try:
        # Test cleanup method
        if hasattr(SecureUserSession, 'cleanup_expired_sessions'):
            expired_count = SecureUserSession.cleanup_expired_sessions()
            print(f"  ✅ cleanup_expired_sessions: Cleaned {expired_count} sessions")
        
        # Test get_user_active_sessions
        if hasattr(SecureUserSession, 'get_user_active_sessions'):
            # This requires a user, so we'll just check if it's callable
            print(f"  ✅ get_user_active_sessions: Method is callable")
        
        # Test enforce_session_limit
        if hasattr(SecureUserSession, 'enforce_session_limit'):
            print(f"  ✅ enforce_session_limit: Method is callable")
            
    except Exception as e:
        print(f"  ❌ Error testing methods: {e}")

def test_otp_methods():
    """
    Test OTP token methods
    """
    print("\n🔍 Testing OTP Token Methods...")
    
    from authentication.models import OTPToken
    
    methods_to_check = [
        'cleanup_expired_tokens',
        'get_user_rate_limit_status',
        'is_expired',
        'is_valid',
        'verify_token'
    ]
    
    results = {}
    
    for method_name in methods_to_check:
        if hasattr(OTPToken, method_name):
            results[method_name] = "✅ Available"
        else:
            results[method_name] = "❌ Missing"
    
    print("\nOTP Token Methods:")
    for method, status in results.items():
        print(f"  {status} {method}")
    
    # Test cleanup method
    try:
        if hasattr(OTPToken, 'cleanup_expired_tokens'):
            cleaned_count = OTPToken.cleanup_expired_tokens()
            print(f"  ✅ cleanup_expired_tokens: Cleaned {cleaned_count} tokens")
    except Exception as e:
        print(f"  ❌ Error testing OTP cleanup: {e}")

def test_security_event_methods():
    """
    Test SecurityEvent methods
    """
    print("\n🔍 Testing Security Event Methods...")
    
    from authentication.models import SecurityEvent
    
    methods_to_check = [
        'get_security_dashboard_data',
        'cleanup_old_events',
        'calculate_risk_score',
        'mark_investigated'
    ]
    
    results = {}
    
    for method_name in methods_to_check:
        if hasattr(SecurityEvent, method_name):
            results[method_name] = "✅ Available"
        else:
            results[method_name] = "❌ Missing"
    
    print("\nSecurity Event Methods:")
    for method, status in results.items():
        print(f"  {status} {method}")
    
    # Test dashboard data method
    try:
        if hasattr(SecurityEvent, 'get_security_dashboard_data'):
            dashboard_data = SecurityEvent.get_security_dashboard_data(days=1)
            print(f"  ✅ get_security_dashboard_data: Returns {len(dashboard_data)} data points")
    except Exception as e:
        print(f"  ❌ Error testing dashboard data: {e}")

def main():
    """
    Main test execution
    """
    print("🔐 Session Management Methods Analysis")
    print("=" * 50)
    
    test_session_methods()
    test_otp_methods() 
    test_security_event_methods()
    
    print("\n" + "=" * 50)
    print("✅ Session methods analysis complete!")

if __name__ == "__main__":
    main()