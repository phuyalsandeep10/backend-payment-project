#!/usr/bin/env python3
"""
Test script to verify commission filtering is working correctly
"""
import os
import sys
import django

# Setup Django environment
sys.path.append('/Users/shishirkafle/Desktop/Frontend/Backend_PRS/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from apps.authentication.models import User
from apps.organization.models import Organization
from apps.permissions.models import Role
from django.db.models import Q, Sum
from decimal import Decimal

def test_commission_filtering():
    """Test commission filtering logic"""
    print("🔍 Testing Commission Filtering Logic")
    print("=" * 50)
    
    # Get all organizations
    orgs = Organization.objects.all()
    print(f"📊 Found {orgs.count()} organizations")
    
    for org in orgs:
        print(f"\n🏢 Organization: {org.name}")
        
        # Get all users in this organization
        all_users = User.objects.filter(organization=org)
        print(f"   👥 Total users: {all_users.count()}")
        
        # Get all roles in this organization
        all_roles = User.objects.filter(organization=org).exclude(role__isnull=True).values('role__name').distinct()
        print(f"   📝 Available roles: {list(all_roles)}")
        
        # Test the exact filtering logic from OrgAdminCommissionView
        salespeople = User.objects.filter(
            organization=org,
            role__name__icontains='sales'  # This is the current filtering logic
        ).select_related('role')
        
        print(f"   🎯 Salespeople found (using icontains='sales'): {salespeople.count()}")
        for sp in salespeople:
            total_sales = sp.created_deals.filter(verification_status='verified').aggregate(
                total=Sum('deal_value')
            )['total'] or Decimal('0.00')
            print(f"      - {sp.first_name} {sp.last_name} ({sp.role.name if sp.role else 'No Role'}) - Total Sales: {total_sales}")
        
        # Test alternative filtering approaches
        print("\n   🔍 Testing alternative filters:")
        
        # Try exact match for "Salesperson"
        exact_salespeople = User.objects.filter(
            organization=org,
            role__name='Salesperson'
        ).select_related('role')
        print(f"   📌 Exact 'Salesperson' match: {exact_salespeople.count()}")
        
        # Try case-insensitive exact match
        ci_salespeople = User.objects.filter(
            organization=org,
            role__name__iexact='salesperson'
        ).select_related('role')
        print(f"   📌 Case-insensitive 'salesperson' match: {ci_salespeople.count()}")
        
        # Try multiple exact matches
        multi_salespeople = User.objects.filter(
            organization=org,
            role__name__in=['Salesperson', 'Senior Salesperson', 'Sales Person', 'Sales']
        ).select_related('role')
        print(f"   📌 Multiple exact matches: {multi_salespeople.count()}")
        
        print("-" * 30)

if __name__ == '__main__':
    test_commission_filtering()