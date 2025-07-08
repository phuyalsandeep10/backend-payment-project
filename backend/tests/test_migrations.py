#!/usr/bin/env python
"""
Migration testing script to detect potential migration conflicts and issues.
"""

import os
import sys
import django
from django.core.management import execute_from_command_line
from django.db import connection
from django.conf import settings

def setup_django():
    """Set up Django environment."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
    django.setup()

def check_column_exists(table_name, column_name):
    """Check if a column exists in a table."""
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = %s AND column_name = %s
        """, [table_name, column_name])
        return cursor.fetchone() is not None

def test_migrations():
    """Test migrations for potential conflicts."""
    print("🔍 Testing migrations for conflicts...")
    
    setup_django()
    
    # Check for specific known conflicts
    conflicts = []
    
    # Check if role_id column already exists in authentication_user table
    if check_column_exists('authentication_user', 'role_id'):
        conflicts.append("Column 'role_id' already exists in 'authentication_user' table")
    
    # Check if user_id column already exists in authentication_userprofile table
    if check_column_exists('authentication_userprofile', 'user_id'):
        conflicts.append("Column 'user_id' already exists in 'authentication_userprofile' table")
    
    # Check if user_id column already exists in authentication_usersession table
    if check_column_exists('authentication_usersession', 'user_id'):
        conflicts.append("Column 'user_id' already exists in 'authentication_usersession' table")
    
    if conflicts:
        print("❌ Migration conflicts detected:")
        for conflict in conflicts:
            print(f"   - {conflict}")
        print("\n💡 These conflicts can be resolved by marking migrations as applied with --fake")
        return False
    
    # Test migration plan
    try:
        print("📋 Testing migration plan...")
        execute_from_command_line(['manage.py', 'makemigrations', '--dry-run'])
        print("✅ Migration plan is valid")
    except Exception as e:
        print(f"❌ Migration plan failed: {e}")
        return False
    
    # Test migration application (dry run)
    try:
        print("🔄 Testing migration application...")
        # Get list of unapplied migrations
        from django.core.management import call_command
        from io import StringIO
        
        output = StringIO()
        call_command('showmigrations', stdout=output)
        output.seek(0)
        
        unapplied = []
        for line in output.readlines():
            if '[ ]' in line:
                unapplied.append(line.strip())
        
        if unapplied:
            print(f"📝 Found {len(unapplied)} unapplied migrations:")
            for migration in unapplied[:5]:  # Show first 5
                print(f"   - {migration}")
            if len(unapplied) > 5:
                print(f"   ... and {len(unapplied) - 5} more")
        else:
            print("✅ All migrations are already applied")
        
        return True
        
    except Exception as e:
        print(f"❌ Migration test failed: {e}")
        return False

if __name__ == '__main__':
    # Add backend directory to Python path
    import os
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, backend_dir)
    
    success = test_migrations()
    sys.exit(0 if success else 1) 