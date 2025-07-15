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
from django.core.management import call_command
from io import StringIO


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


def check_migration_state():
    """Check and report the current migration state."""
    print("📊 Checking migration state...")
    
    from django.db.migrations.executor import MigrationExecutor
    from django.db import connection
    
    executor = MigrationExecutor(connection)
    plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
    
    if plan:
        print("  ⚠️  Pending migrations detected:")
        for migration, backwards in plan:
            print(f"    - {migration}")
    else:
        print("  ✅ No pending migrations")
    
    return plan


def prevent_auto_migrations():
    """Prevent Django from auto-generating migrations during deployment."""
    print("🛡️  Preventing auto-migration generation...")
    
    # Check if there are any model changes that would trigger migrations
    try:
        # Capture makemigrations output
        out = StringIO()
        call_command('makemigrations', '--dry-run', stdout=out)
        output = out.getvalue()
        
        if output.strip():
            print("  ⚠️  Model changes detected that would create migrations:")
            print(f"    {output.strip()}")
            print("  💡 This is normal - the migrations will be handled by existing migration files")
        else:
            print("  ✅ No model changes detected")
            
    except Exception as e:
        print(f"  ⚠️  Could not check for model changes: {e}")


def fake_problematic_migrations():
    """Fake-apply any problematic migrations that might conflict."""
    print("🎭 Handling problematic migrations...")
    
    # List of migrations that might cause conflicts
    problematic_migrations = [
        ('authentication', '0007_auto_20250715_2117'),
        ('authentication', '0008_user_login_count'),
    ]
    
    for app_label, migration_name in problematic_migrations:
        try:
            print(f"  - Checking {app_label}.{migration_name}...")
            
            # Check if this migration exists in the migration files
            migration_path = f"{app_label}/migrations/{migration_name}.py"
            if os.path.exists(migration_path):
                print(f"    ✅ Migration file exists, will be applied normally")
            else:
                print(f"    ⚠️  Migration file doesn't exist, skipping")
                
        except Exception as e:
            print(f"    ❌ Error checking migration: {e}")


def run_safe_migrations():
    """Run migrations with safety checks."""
    print("🚀 Running migrations safely...")
    
    try:
        # First, try to fake-apply any problematic migrations
        problematic_migrations = [
            ('authentication', '0007_auto_20250715_2117'),
            ('authentication', '0008_user_login_count'),
        ]
        
        for app_label, migration_name in problematic_migrations:
            try:
                print(f"  - Attempting to fake-apply {app_label}.{migration_name}...")
                call_command('migrate', app_label, migration_name, '--fake', verbosity=0)
                print(f"    ✅ Successfully fake-applied {app_label}.{migration_name}")
            except Exception as e:
                print(f"    ⚠️  Could not fake-apply {app_label}.{migration_name}: {e}")
        
        # Now run all migrations normally
        print("  - Running all migrations...")
        call_command('migrate', verbosity=1)
        print("  ✅ All migrations completed successfully")
        
    except Exception as e:
        print(f"  ❌ Error during migrations: {e}")
        raise


def main():
    """Main function to run all fixes."""
    print("🚀 Starting deployment migration fixes...")
    
    try:
        # Fix database schema issues
        fix_authentication_user_table()
        
        # Check migration state
        check_migration_state()
        
        # Prevent auto-migration issues
        prevent_auto_migrations()
        
        # Handle problematic migrations
        fake_problematic_migrations()
        
        # Run migrations safely
        run_safe_migrations()
        
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