#!/usr/bin/env python
"""
Database connection checker for troubleshooting deployment issues.
"""
import os
import sys
import django
from django.conf import settings

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

def check_database_connection():
    """Check database connectivity and display connection details."""
    print("🔍 Database Connection Checker")
    print("=" * 50)
    
    # Get database settings
    db_settings = settings.DATABASES['default']
    
    print(f"Database Engine: {db_settings['ENGINE']}")
    print(f"Database Name: {db_settings['NAME']}")
    print(f"Database Host: {db_settings['HOST']}")
    print(f"Database Port: {db_settings['PORT']}")
    print(f"Database User: {db_settings['USER']}")
    print(f"Password Set: {'Yes' if db_settings['PASSWORD'] else 'No'}")
    
    # Check environment variables
    print("\n🔧 Environment Variables:")
    env_vars = ['DB_NAME', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_PORT', 'DB_ENGINE']
    for var in env_vars:
        value = os.getenv(var)
        if value:
            # Mask password
            if 'PASSWORD' in var:
                value = '*' * len(value)
            print(f"  {var}: {value}")
        else:
            print(f"  {var}: Not set")
    
    # Try to connect
    print("\n🔌 Testing Connection...")
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT version();")
            version = cursor.fetchone()
            print(f"✅ Connection successful!")
            print(f"   PostgreSQL version: {version[0]}")
            
            # Check if our database exists
            cursor.execute("SELECT current_database();")
            current_db = cursor.fetchone()
            print(f"   Current database: {current_db[0]}")
            
    except Exception as e:
        print(f"❌ Connection failed: {str(e)}")
        print("\n🔧 Troubleshooting tips:")
        print("   1. Check if database service is running")
        print("   2. Verify environment variables are correct")
        print("   3. Ensure database and web service are linked")
        print("   4. Wait a few minutes for database to initialize")
        return False
    
    return True

if __name__ == '__main__':
    check_database_connection() 