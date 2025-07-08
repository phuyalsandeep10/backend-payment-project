#!/usr/bin/env python
"""
Migration testing script to run before deployment.
This script tests migrations on a copy of the production database schema.
"""
import os
import sys
import django
from django.core.management import execute_from_command_line
from django.db import connection
from django.conf import settings

def test_migrations():
    """Test migrations on a temporary database."""
    print("🔍 Testing migrations...")
    
    # Create a temporary database for testing
    test_db_name = f"test_migrations_{os.getpid()}"
    
    try:
        # Create test database
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE {test_db_name}")
        
        # Update settings to use test database
        settings.DATABASES['default']['NAME'] = test_db_name
        
        # Run migrations
        execute_from_command_line(['manage.py', 'migrate', '--verbosity=0'])
        
        # Test that the app can start
        execute_from_command_line(['manage.py', 'check', '--deploy'])
        
        print("✅ Migration test passed!")
        return True
        
    except Exception as e:
        print(f"❌ Migration test failed: {e}")
        return False
        
    finally:
        # Clean up test database
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"DROP DATABASE IF EXISTS {test_db_name}")
        except:
            pass

if __name__ == "__main__":
    # Change to the backend directory to ensure Django can find modules
    import subprocess
    import os
    
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(script_dir, '..')
    
    # Change to backend directory
    os.chdir(backend_dir)
    
    # Add backend directory to Python path
    sys.path.insert(0, backend_dir)
    
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
    django.setup()
    
    success = test_migrations()
    sys.exit(0 if success else 1) 