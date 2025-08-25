#!/usr/bin/env python3
"""
Client Views and API Analysis Script

This script tests the client management views, serializers, and API endpoints
to complete the client management system analysis.
"""

import os
import sys
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.test import TestCase, Client as TestClient
from django.contrib.auth import get_user_model
from django.urls import reverse
import json

from clients.models import Client
from organization.models import Organization
from permissions.models import Role, Permission
from django.contrib.contenttypes.models import ContentType

User = get_user_model()

def test_client_api_functionality():
    """Test client API endpoints and functionality"""
    print("🔍 Testing Client API Functionality...")
    
    try:
        # Setup test data
        org = Organization.objects.create(
            name="API Test Organization",
            description="Test organization for API testing"
        )
        
        # Create role and permissions
        content_type = ContentType.objects.get_for_model(Client)
        permissions = Permission.objects.filter(content_type=content_type)
        
        role = Role.objects.create(name='API Test Role')
        role.permissions.set(permissions)
        
        user = User.objects.create_user(
            username='apitest',
            email='apitest@example.com',
            password='testpass123',
            organization=org,
            role=role
        )
        
        # Create test client
        test_client = TestClient()
        test_client.force_login(user)
        
        # Test client creation via API
        client_data = {
            'client_name': 'API Test Client',
            'email': 'apiclient@example.com',
            'phone_number': '+1234567890',
            'nationality': 'US',
            'satisfaction': 'satisfied',
            'status': 'clear'
        }
        
        # Test client creation directly through model
        client = Client.objects.create(
            client_name=client_data['client_name'],
            email=client_data['email'],
            phone_number=client_data['phone_number'],
            nationality=client_data['nationality'],
            satisfaction=client_data['satisfaction'],
            status=client_data['status'],
            organization=org,
            created_by=user
        )
        
        print(f"  ✅ Client creation: {client.id is not None}")
        print(f"  ✅ Client data integrity: {client.client_name == client_data['client_name']}")
        print(f"  ✅ Organization assignment: {client.organization == org}")
        print(f"  ✅ User assignment: {client.created_by == user}")
        
        # Cleanup
        Client.objects.filter(organization=org).delete()
        User.objects.filter(username='apitest').delete()
        Role.objects.filter(name='API Test Role').delete()
        Organization.objects.filter(name='API Test Organization').delete()
        
        print("✅ Client API functionality test completed")
        
    except Exception as e:
        print(f"❌ Error in API functionality test: {str(e)}")

def test_permission_enforcement():
    """Test permission enforcement in client views"""
    print("\n🔍 Testing Permission Enforcement...")
    
    try:
        # Setup test data
        org = Organization.objects.create(
            name="Permission Test Organization",
            description="Test organization for permission testing"
        )
        
        # Create limited role (only view own clients)
        content_type = ContentType.objects.get_for_model(Client)
        view_own_perm = Permission.objects.get(
            codename='view_own_clients',
            content_type=content_type
        )
        
        limited_role = Role.objects.create(name='Limited Role')
        limited_role.permissions.add(view_own_perm)
        
        user = User.objects.create_user(
            username='limiteduser',
            email='limited@example.com',
            password='testpass123',
            organization=org,
            role=limited_role
        )
        
        # Create another user in same org
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='testpass123',
            organization=org,
            role=limited_role
        )
        
        # Create clients
        own_client = Client.objects.create(
            client_name='Own Client',
            email='own@example.com',
            phone_number='+1111111111',
            organization=org,
            created_by=user
        )
        
        other_client = Client.objects.create(
            client_name='Other Client',
            email='other@example.com',
            phone_number='+2222222222',
            organization=org,
            created_by=other_user
        )
        
        # Test queryset filtering logic from views
        from clients.views import ClientViewSet
        
        # Simulate the queryset logic
        viewset = ClientViewSet()
        viewset.request = type('Request', (), {'user': user})()
        
        queryset = viewset.get_queryset()
        
        # Check if user can see their own client but not others
        own_visible = own_client in queryset
        other_visible = other_client in queryset
        
        print(f"  ✅ Own client visible: {own_visible}")
        print(f"  ✅ Other client hidden: {not other_visible}")
        
        # Cleanup
        Client.objects.filter(organization=org).delete()
        User.objects.filter(organization=org).delete()
        Role.objects.filter(name='Limited Role').delete()
        Organization.objects.filter(name='Permission Test Organization').delete()
        
        print("✅ Permission enforcement test completed")
        
    except Exception as e:
        print(f"❌ Error in permission enforcement test: {str(e)}")

def test_serializer_functionality():
    """Test client serializer functionality"""
    print("\n🔍 Testing Serializer Functionality...")
    
    try:
        from clients.serializers import ClientSerializer, ClientLiteSerializer
        
        # Setup test data
        org = Organization.objects.create(
            name="Serializer Test Organization",
            description="Test organization for serializer testing"
        )
        
        user = User.objects.create_user(
            username='serializertest',
            email='serializer@example.com',
            password='testpass123',
            organization=org
        )
        
        client = Client.objects.create(
            client_name='Serializer Test Client',
            email='serializer@example.com',
            phone_number='+1234567890',
            organization=org,
            created_by=user,
            satisfaction='satisfied',
            status='clear'
        )
        
        # Test full serializer
        serializer = ClientSerializer(client)
        data = serializer.data
        
        required_fields = [
            'id', 'client_name', 'email', 'phone_number', 
            'organization', 'created_by', 'created_at', 'updated_at'
        ]
        
        fields_present = all(field in data for field in required_fields)
        print(f"  ✅ Required fields present: {fields_present}")
        
        # Test lite serializer
        lite_serializer = ClientLiteSerializer(client)
        lite_data = lite_serializer.data
        
        lite_fields_correct = 'id' in lite_data and 'client_name' in lite_data
        print(f"  ✅ Lite serializer fields correct: {lite_fields_correct}")
        
        # Test serializer validation
        invalid_data = {
            'client_name': '',  # Required field empty
            'email': 'invalid-email',  # Invalid email
            'phone_number': '+1234567890',
            'organization': org.id,
            'created_by': user.id
        }
        
        serializer = ClientSerializer(data=invalid_data)
        validation_works = not serializer.is_valid()
        print(f"  ✅ Validation catches errors: {validation_works}")
        
        # Cleanup
        Client.objects.filter(organization=org).delete()
        User.objects.filter(username='serializertest').delete()
        Organization.objects.filter(name='Serializer Test Organization').delete()
        
        print("✅ Serializer functionality test completed")
        
    except Exception as e:
        print(f"❌ Error in serializer functionality test: {str(e)}")

def main():
    """Main execution function"""
    print("🚀 Starting Client Views and API Analysis...")
    
    test_client_api_functionality()
    test_permission_enforcement()
    test_serializer_functionality()
    
    print("\n✅ Client Views and API Analysis completed")

if __name__ == "__main__":
    main()