#!/usr/bin/env python
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from clients.models import Client
from deals.models import Deal

# Find the client
client = Client.objects.filter(client_name__icontains='Avinash').first()
print(f"Client: {client.client_name if client else 'Not found'}")

if client:
    print(f"Client status: {client.status}")
    print(f"Client ID: {client.id}")
    
    # Get deals for this client
    deals = Deal.objects.filter(client=client)
    print(f"Deals count: {deals.count()}")
    
    for deal in deals:
        print(f"Deal: {deal.deal_id}")
        print(f"  Payment status: {deal.payment_status}")
        print(f"  Client status: {deal.client_status}")
        print(f"  Deal value: {deal.deal_value}")
        
        # Get payments for this deal
        payments = deal.payments.all()
        total_paid = sum(float(p.received_amount) for p in payments)
        print(f"  Total paid: {total_paid}")
        print(f"  Outstanding: {float(deal.deal_value) - total_paid}")
        print("---") 