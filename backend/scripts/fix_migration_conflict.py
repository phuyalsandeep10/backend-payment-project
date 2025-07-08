#!/usr/bin/env python
"""
Script to fix migration conflicts in production.
This script handles cases where migrations try to add columns that already exist.
"""

import os
import sys
import django
from django.core.management import execute_from_command_line

def fix_migration_conflict():
    """Fix the role_id column migration conflict."""
    print("🔧 Fixing migration conflict...")
    
    # Set up Django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')
    django.setup()
    
    try:
        # Mark the problematic migration as applied without running it
        print("📝 Marking migration 0003_add_role_and_user_permissions as applied...")
        execute_from_command_line([
            'manage.py', 'migrate', 'authentication', '0003_add_role_and_user_permissions', '--fake'
        ])
        
        # Run any remaining migrations
        print("🔄 Running remaining migrations...")
        execute_from_command_line(['manage.py', 'migrate'])
        
        print("✅ Migration conflict fixed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error fixing migration conflict: {e}")
        return False

if __name__ == '__main__':
    # Add backend directory to Python path
    import os
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, backend_dir)
    
    success = fix_migration_conflict()
    sys.exit(0 if success else 1) 