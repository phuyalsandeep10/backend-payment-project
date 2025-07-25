#!/usr/bin/env python
"""
Test script to verify DATABASE_URL configuration works correctly.
"""
import os
import sys
import django
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent / 'backend'
sys.path.insert(0, str(backend_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

def test_database_url_parsing():
    """Test that DATABASE_URL is parsed correctly."""
    print("🧪 Testing DATABASE_URL Configuration")
    print("=" * 50)
    
    try:
        django.setup()
        from django.conf import settings
        
        db_settings = settings.DATABASES['default']
        
        print(f"✅ Database configuration loaded successfully")
        print(f"   Engine: {db_settings['ENGINE']}")
        print(f"   Name: {db_settings['NAME']}")
        print(f"   Host: {db_settings['HOST']}")
        print(f"   Port: {db_settings['PORT']}")
        print(f"   User: {db_settings['USER']}")
        print(f"   Password Set: {'Yes' if db_settings['PASSWORD'] else 'No'}")
        
        # Check if it's using DATABASE_URL
        if os.getenv('DATABASE_URL'):
            print(f"   Source: DATABASE_URL (recommended)")
        else:
            print(f"   Source: Individual environment variables (legacy)")
        
        return True
        
    except Exception as e:
        print(f"❌ Error loading database configuration: {e}")
        return False

def test_database_connection():
    """Test actual database connection."""
    print(f"\n🔌 Testing Database Connection")
    print("=" * 50)
    
    try:
        from django.db import connection
        
        # Test connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT version();")
            version = cursor.fetchone()
            print(f"✅ Database connection successful!")
            print(f"   Version: {version[0]}")
            
            # Check current database
            cursor.execute("SELECT current_database();")
            current_db = cursor.fetchone()
            print(f"   Database: {current_db[0]}")
            
            return True
            
    except Exception as e:
        print(f"❌ Database connection failed: {str(e)}")
        print(f"   Error type: {type(e).__name__}")
        return False

def show_environment_info():
    """Show current environment information."""
    print(f"\n🔍 Environment Information")
    print("=" * 50)
    
    # Check for DATABASE_URL
    database_url = os.getenv('DATABASE_URL')
    if database_url:
        print("✅ DATABASE_URL is set")
        # Show a masked version
        if '://' in database_url:
            parts = database_url.split('://')
            if len(parts) == 2:
                scheme = parts[0]
                rest = parts[1]
                if '@' in rest:
                    user_pass, host_db = rest.split('@', 1)
                    if ':' in user_pass:
                        user, password = user_pass.split(':', 1)
                        masked_password = '*' * min(len(password), 8)
                        masked_url = f"{scheme}://{user}:{masked_password}@{host_db}"
                        print(f"   Format: {masked_url}")
    else:
        print("❌ DATABASE_URL is not set")
    
    # Check legacy variables
    legacy_vars = ['DB_NAME', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_PORT', 'DB_ENGINE']
    legacy_count = 0
    
    for var in legacy_vars:
        if os.getenv(var):
            legacy_count += 1
    
    if legacy_count > 0:
        print(f"⚠️  {legacy_count} legacy DB_* variables are set")
    else:
        print("✅ No legacy DB_* variables are set")

def main():
    """Main test function."""
    print("🚀 DATABASE_URL Configuration Test")
    print("=" * 60)
    
    # Show environment info
    show_environment_info()
    
    # Test configuration loading
    config_ok = test_database_url_parsing()
    
    # Test connection
    connection_ok = test_database_connection()
    
    # Summary
    print(f"\n📊 Test Summary")
    print("=" * 50)
    print(f"Configuration Loading: {'✅ PASS' if config_ok else '❌ FAIL'}")
    print(f"Database Connection: {'✅ PASS' if connection_ok else '❌ FAIL'}")
    
    if config_ok and connection_ok:
        print("\n🎉 All tests passed! DATABASE_URL configuration is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Check the details above.")
        sys.exit(1)

if __name__ == '__main__':
    main() 