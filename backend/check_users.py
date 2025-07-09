#!/usr/bin/env python3
import os
import sys
import django

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

# Setup Django
django.setup()

from authentication.models import User
from clients.models import Client

print("👤 All Users:")
for user in User.objects.filter(role__name='salesperson'):
    print(f"   ID: {user.id}, Email: {user.email}, Name: {user.get_full_name()}")

print("\n🔗 Client-Salesperson Relationships:")
for client in Client.objects.all()[:15]:
    sp_email = client.salesperson.email if client.salesperson else 'None'
    print(f"   Client: {client.client_name} -> Salesperson: {sp_email}")

print(f"\n📊 Summary:")
print(f"   Total salesperson users: {User.objects.filter(role__name='salesperson').count()}")
print(f"   Clients with no salesperson: {Client.objects.filter(salesperson__isnull=True).count()}")
print(f"   Clients with salesperson: {Client.objects.filter(salesperson__isnull=False).count()}") 