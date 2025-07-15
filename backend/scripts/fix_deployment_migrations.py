#!/usr/bin/env python
"""
Deployment migration fix script.
Run this before Django migrations to resolve common deployment conflicts.
"""

import os
import sys
import django
from django.conf import settings

# Add the backend directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
django.setup()

from django.db import connection


def fix_authentication_user_table():
    """Fix common issues with authentication_user table."""
    print("🔧 Fixing authentication_user table...")
    
    with connection.cursor() as cursor:
        # Check current table structure
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'authentication_user'
        """)
        existing_columns = [row[0] for row in cursor.fetchall()]
        
        # Remove avatar column if it exists (shouldn't be there)
        if 'avatar' in existing_columns:
            print("  - Removing avatar column...")
            cursor.execute("ALTER TABLE authentication_user DROP COLUMN avatar")
            print("  ✅ avatar column removed")
        
        # Add login_count column if it doesn't exist
        if 'login_count' not in existing_columns:
            print("  - Adding login_count column...")
            cursor.execute("ALTER TABLE authentication_user ADD COLUMN login_count integer DEFAULT 0")
            print("  ✅ login_count column added")
        
        print("✅ authentication_user table fixed")


def main():
    """Main function to run all fixes."""
    print("🚀 Starting deployment migration fixes...")
    
    try:
        fix_authentication_user_table()
        print("✅ All deployment migration fixes completed successfully!")
        return 0
    except Exception as e:
        print(f"❌ Error during migration fixes: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 