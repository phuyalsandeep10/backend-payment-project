#!/usr/bin/env python
"""
Test Verifier Permissions Script
Tests if the verifier user can access verifier dashboard endpoints.
"""

import os
import sys
import django

# Add the backend directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import RequestFactory
from django.contrib.auth.models import AnonymousUser
from authentication.models import User
from Verifier_dashboard.permissions import HasVerifierPermission
from Verifier_dashboard.views import payment_stats


def test_verifier_permissions():
    """Test verifier permissions directly."""
    print("🧪 Testing Verifier Permissions...")
    
    # Get verifier user
    try:
        verifier_user = User.objects.get(username='verifier')
        print(f"✅ Found verifier user: {verifier_user.email}")
    except User.DoesNotExist:
        print("❌ Verifier user not found!")
        return
    
    # Create a mock request
    factory = RequestFactory()
    request = factory.get('/api/verifier/dashboard/')
    request.user = verifier_user
    
    # Test the permission class directly
    permission = HasVerifierPermission()
    
    print(f"\n🔍 Testing permission for user:")
    print(f"   - User: {verifier_user.email}")
    print(f"   - Role: {verifier_user.role}")
    print(f"   - Role name: '{verifier_user.role.name}'")
    print(f"   - Role name (lower): '{verifier_user.role.name.lower()}'")
    print(f"   - Role name (strip): '{verifier_user.role.name.strip()}'")
    print(f"   - Role name (normalized): '{verifier_user.role.name.strip().lower()}'")
    
    # Check if user has verifier permissions
    user_permissions = list(verifier_user.role.permissions.values_list('codename', flat=True))
    print(f"   - User permissions: {user_permissions}")
    
    # Check specific permissions
    required_permissions = ['view_payment_verification_dashboard']
    for perm in required_permissions:
        has_perm = perm in user_permissions
        print(f"   - Has '{perm}': {has_perm}")
    
    # Test the permission class
    has_permission = permission.has_permission(request, None)
    print(f"\n🔍 Permission check result: {has_permission}")
    
    # Test with a mock view
    class MockView:
        def __init__(self, name):
            self.__name__ = name
    
    mock_view = MockView('payment_stats')
    has_permission_with_view = permission.has_permission(request, mock_view)
    print(f"🔍 Permission check with 'payment_stats' view: {has_permission_with_view}")
    
    return has_permission


def test_view_function():
    """Test the actual view function."""
    print("\n🧪 Testing View Function...")
    
    # Get verifier user
    try:
        verifier_user = User.objects.get(username='verifier')
    except User.DoesNotExist:
        print("❌ Verifier user not found!")
        return
    
    # Create a mock request
    factory = RequestFactory()
    request = factory.get('/api/verifier/dashboard/')
    request.user = verifier_user
    
    # Test the view function directly
    try:
        from rest_framework.test import force_authenticate
        force_authenticate(request, user=verifier_user)
        
        # This will test the actual view function
        response = payment_stats(request)
        print(f"✅ View function response status: {response.status_code}")
        print(f"✅ View function response: {response.data}")
        
    except Exception as e:
        print(f"❌ Error testing view function: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main function."""
    print("🧪 Verifier Permissions Test")
    print("=" * 50)
    
    # Test permissions
    test_verifier_permissions()
    
    # Test view function
    test_view_function()
    
    print("\n✅ Test completed!")


if __name__ == "__main__":
    main() 