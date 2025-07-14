#!/usr/bin/env python
import os
import sys
import django
from datetime import datetime, timedelta

# Add the backend directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from deals.models import Deal
from django.utils import timezone

def check_recent_deals():
    """Check for recent deals in the database"""
    print("=" * 80)
    print("RECENT DEALS DATABASE CHECK")
    print("=" * 80)
    
    # Get current time
    now = timezone.now()
    
    # Check deals created in the last 7 days
    last_week = now - timedelta(days=7)
    recent_deals = Deal.objects.filter(created_at__gte=last_week).order_by('-created_at')
    
    print(f"\nDeals created in the last 7 days: {recent_deals.count()}")
    print("-" * 80)
    
    if recent_deals.exists():
        for deal in recent_deals:
            print(f"Deal ID: {deal.deal_id}")
            print(f"Deal Name: {deal.deal_name}")
            print(f"Client: {deal.client.client_name if deal.client else 'N/A'}")
            print(f"Organization: {deal.organization.name if deal.organization else 'N/A'}")
            print(f"Deal Value: {deal.deal_value} {deal.currency}")
            print(f"Payment Status: {deal.payment_status}")
            print(f"Verification Status: {deal.verification_status}")
            print(f"Created By: {deal.created_by.username if deal.created_by else 'N/A'}")
            print(f"Created At: {deal.created_at}")
            print(f"Updated At: {deal.updated_at}")
            print("-" * 40)
    else:
        print("No deals found in the last 7 days.")
    
    # Check all deals (last 20)
    print(f"\nLast 20 deals in the database:")
    print("-" * 80)
    
    all_recent_deals = Deal.objects.all().order_by('-created_at')[:20]
    
    if all_recent_deals.exists():
        for deal in all_recent_deals:
            print(f"Deal ID: {deal.deal_id}")
            print(f"Deal Name: {deal.deal_name}")
            print(f"Client: {deal.client.client_name if deal.client else 'N/A'}")
            print(f"Deal Value: {deal.deal_value} {deal.currency}")
            print(f"Payment Status: {deal.payment_status}")
            print(f"Verification Status: {deal.verification_status}")
            print(f"Created At: {deal.created_at}")
            print("-" * 40)
    else:
        print("No deals found in the database.")
    
    # Total count
    total_deals = Deal.objects.count()
    print(f"\nTotal deals in database: {total_deals}")
    
    # Check deals by status
    print(f"\nDeals by status:")
    print("-" * 40)
    for status in ['pending', 'verified', 'rejected']:
        count = Deal.objects.filter(verification_status=status).count()
        print(f"{status.capitalize()}: {count}")
    
    print("=" * 80)

if __name__ == "__main__":
    try:
        check_recent_deals()
    except Exception as e:
        print(f"Error checking deals: {e}")
        import traceback
        traceback.print_exc() 