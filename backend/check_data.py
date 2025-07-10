#!/usr/bin/env python3
import os
import sys
import django

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

# Setup Django
django.setup()

from clients.models import Client
from deals.models import Payment

print(f"📊 Database Overview:")
print(f"   Clients: {Client.objects.count()}")
print(f"   Payments: {Payment.objects.count()}")
print()

print("👥 Client Details:")
for c in Client.objects.all()[:10]:
    print(f"   ID: {c.id}, Name: {c.client_name}, Salesperson: {c.salesperson}")
print()

print("💳 Payment Details:")
for p in Payment.objects.all()[:10]:
    print(f"   ID: {p.id}, Client: {p.client.client_name}, Amount: {p.amount}, Status: {p.status}") 