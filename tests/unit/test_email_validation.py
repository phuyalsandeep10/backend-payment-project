#!/usr/bin/env python
"""
Quick test script to verify email validation functionality in UserCreateSerializer
"""
import os
import sys
import django

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from authentication.serializers import UserCreateSerializer
from authentication.models import User
from organization.models import Organization
from permissions.models import Role
from django.test import RequestFactory
from django.contrib.auth import get_user_model

def test_email_validation():
    """Test email validation in UserCreateSerializer"""
    print("Testing email validation in UserCreateSerializer...")
    
    # Create a mock request with a user
    factory = RequestFactory()
    request = factory.post('/test/')
    
    # Get or create a test organization
    org, created = Organization.objects.get_or_create(
        name="Test Organization",
        defaults={'description': 'Test org for validation'}
    )
    
    # Get or create a test role
    role, created = Role.objects.get_or_create(
        name="Test Role",
        organization=org
    )
    
    # Create a test user to act as the requesting user
    test_user = User.objects.filter(email='test_admin@example.com').first()
    if not test_user:
        test_user = User.objects.create_user(
            email='test_admin@example.com',
            username='test_admin',
            password='testpass123',
            organization=org,
            is_superuser=True
        )
    
    request.user = test_user
    
    # Test data with various email formats
    test_cases = [
        {
            'name': 'Normal email',
            'data': {
                'email': 'user@example.com',
                'first_name': 'Test',
                'last_name': 'User',
                'role': 'Test Role',
                'organization': org.id
            },
            'should_pass': True
        },
        {
            'name': 'Email with whitespace',
            'data': {
                'email': '  USER@EXAMPLE.COM  ',
                'first_name': 'Test',
                'last_name': 'User2',
                'role': 'Test Role',
                'organization': org.id
            },
            'should_pass': True,
            'expected_email': 'user@example.com'
        },
        {
            'name': 'Uppercase email',
            'data': {
                'email': 'UPPERCASE@EXAMPLE.COM',
                'first_name': 'Test',
                'last_name': 'User3',
                'role': 'Test Role',
                'organization': org.id
            },
            'should_pass': True,
            'expected_email': 'uppercase@example.com'
        },
        {
            'name': 'Invalid email format',
            'data': {
                'email': 'invalid-email',
                'first_name': 'Test',
                'last_name': 'User4',
                'role': 'Test Role',
                'organization': org.id
            },
            'should_pass': False
        }
    ]
    
    for test_case in test_cases:
        print(f"\n--- Testing: {test_case['name']} ---")
        
        serializer = UserCreateSerializer(data=test_case['data'], context={'request': request})
        
        if test_case['should_pass']:
            if serializer.is_valid():
                print(f"✅ Validation passed")
                validated_email = serializer.validated_data.get('email')
                expected_email = test_case.get('expected_email', test_case['data']['email'].strip().lower())
                
                if validated_email == expected_email:
                    print(f"✅ Email normalized correctly: {test_case['data']['email']} -> {validated_email}")
                else:
                    print(f"❌ Email normalization failed: expected {expected_email}, got {validated_email}")
            else:
                print(f"❌ Validation failed unexpectedly: {serializer.errors}")
        else:
            if not serializer.is_valid():
                print(f"✅ Validation correctly failed: {serializer.errors}")
            else:
                print(f"❌ Validation should have failed but passed")
    
    # Test duplicate email detection
    print(f"\n--- Testing duplicate email detection ---")
    
    # First, create a user
    duplicate_data = {
        'email': 'duplicate@example.com',
        'first_name': 'First',
        'last_name': 'User',
        'role': 'Test Role',
        'organization': org.id
    }
    
    serializer1 = UserCreateSerializer(data=duplicate_data, context={'request': request})
    if serializer1.is_valid():
        try:
            user1 = serializer1.save()
            print(f"✅ First user created: {user1.email}")
            
            # Now try to create another user with the same email (different case)
            duplicate_data2 = {
                'email': 'DUPLICATE@EXAMPLE.COM',  # Same email, different case
                'first_name': 'Second',
                'last_name': 'User',
                'role': 'Test Role',
                'organization': org.id
            }
            
            serializer2 = UserCreateSerializer(data=duplicate_data2, context={'request': request})
            if not serializer2.is_valid():
                print(f"✅ Duplicate email correctly detected: {serializer2.errors}")
            else:
                print(f"❌ Duplicate email not detected")
                
        except Exception as e:
            print(f"❌ Error creating first user: {e}")
    else:
        print(f"❌ Failed to create first user: {serializer1.errors}")
    
    print("\n--- Email validation test completed ---")

if __name__ == '__main__':
    test_email_validation()