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
            
            # Test a simple query
            cursor.execute("SELECT 1;")
            result = cursor.fetchone()
            print(f"   Simple query test: {result[0]}")
            
    except Exception as e:
        print(f"❌ Connection failed: {str(e)}")
        print(f"   Error type: {type(e).__name__}")
        
        # Provide specific troubleshooting based on error type
        if "Name or service not known" in str(e):
            print("\n🔧 This error indicates DNS resolution failure.")
            print("   Possible causes:")
            print("   1. Database hostname is incorrect")
            print("   2. Database service is not running")
            print("   3. Network connectivity issues")
            print("   4. Environment variables are wrong")
        elif "Connection refused" in str(e):
            print("\n🔧 This error indicates the database is not accepting connections.")
            print("   Possible causes:")
            print("   1. Database service is not running")
            print("   2. Wrong port number")
            print("   3. Firewall blocking connection")
        elif "authentication failed" in str(e).lower():
            print("\n🔧 This error indicates authentication failure.")
            print("   Possible causes:")
            print("   1. Wrong username/password")
            print("   2. User doesn't exist")
            print("   3. User doesn't have permission")
        
        print("\n🔧 Troubleshooting tips:")
        print("   1. Check if database service is running")
        print("   2. Verify environment variables are correct")
        print("   3. Ensure database and web service are linked")
        print("   4. Wait a few minutes for database to initialize")
        print("   5. Check Render dashboard for database status")
        return False
    
    return True

def test_django_check():
    """Test Django's built-in check command."""
    print("\n🔍 Testing Django check command...")
    try:
        from django.core.management import execute_from_command_line
        # Capture output
        import io
        from contextlib import redirect_stdout, redirect_stderr
        
        f = io.StringIO()
        with redirect_stdout(f), redirect_stderr(f):
            execute_from_command_line(['manage.py', 'check', '--database', 'default'])
        
        output = f.getvalue()
        print("✅ Django check passed")
        print(f"   Output: {output.strip()}")
        return True
    except Exception as e:
        print(f"❌ Django check failed: {str(e)}")
        return False

if __name__ == '__main__':
    print("Starting database connection tests...\n")
    
    # Test 1: Direct connection
    connection_ok = check_database_connection()
    
    # Test 2: Django check
    django_check_ok = test_django_check()
    
    print("\n" + "=" * 50)
    print("SUMMARY:")
    print(f"Direct Connection: {'✅ OK' if connection_ok else '❌ FAILED'}")
    print(f"Django Check: {'✅ OK' if django_check_ok else '❌ FAILED'}")
    
    if connection_ok and django_check_ok:
        print("\n🎉 All tests passed! Database is ready.")
    else:
        print("\n⚠️  Some tests failed. Check the details above.")
        sys.exit(1) 