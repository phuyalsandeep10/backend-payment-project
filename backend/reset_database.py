#!/usr/bin/env python
"""
Database reset script for fresh deployments.
This script safely resets the database and runs all necessary setup.
"""
import os
import sys
import django
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

def reset_database():
    """Reset the database for fresh deployment."""
    print("🗑️  Resetting Database for Fresh Deployment")
    print("=" * 60)
    
    try:
        django.setup()
        from django.core.management import call_command
        from django.db import connection
        
        # Step 1: Drop all tables (if they exist)
        print("Step 1: Dropping existing tables...")
        with connection.cursor() as cursor:
            # Disable foreign key checks temporarily
            cursor.execute("SET session_replication_role = replica;")
            
            # Get all table names
            cursor.execute("""
                SELECT tablename FROM pg_tables 
                WHERE schemaname = 'public' 
                AND tablename NOT LIKE 'pg_%'
                AND tablename NOT LIKE 'sql_%';
            """)
            tables = [row[0] for row in cursor.fetchall()]
            
            if tables:
                print(f"Found {len(tables)} tables to drop")
                for table in tables:
                    try:
                        cursor.execute(f'DROP TABLE IF EXISTS "{table}" CASCADE;')
                        print(f"  ✅ Dropped {table}")
                    except Exception as e:
                        print(f"  ⚠️  Could not drop {table}: {e}")
            else:
                print("No existing tables found")
            
            # Re-enable foreign key checks
            cursor.execute("SET session_replication_role = DEFAULT;")
        
        # Step 2: Run migrations
        print("\nStep 2: Running migrations...")
        call_command('migrate', verbosity=1)
        print("✅ Migrations completed")
        
        # Step 3: Create superuser
        print("\nStep 3: Creating superuser...")
        call_command('setup_superadmin', verbosity=1)
        print("✅ Superuser created")
        
        # Step 4: Setup permissions
        print("\nStep 4: Setting up permissions...")
        call_command('setup_permissions', verbosity=1)
        print("✅ Permissions setup completed")
        
        # Step 5: Initialize application
        print("\nStep 5: Initializing application...")
        call_command('initialize_app', verbosity=1)
        print("✅ Application initialized")
        
        print("\n🎉 Database reset completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error resetting database: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def main():
    """Main function."""
    print("🚀 Database Reset Tool")
    print("=" * 60)
    
    # Confirm this is what the user wants
    print("⚠️  WARNING: This will completely reset your database!")
    print("   All existing data will be lost.")
    print("   This is intended for fresh deployments only.")
    print()
    
    # In production (non-interactive), proceed automatically
    if os.getenv('RENDER') or os.getenv('PRODUCTION'):
        print("Production environment detected - proceeding with reset...")
        success = reset_database()
    else:
        # In development, ask for confirmation
        response = input("Are you sure you want to continue? (yes/no): ")
        if response.lower() in ['yes', 'y']:
            success = reset_database()
        else:
            print("Database reset cancelled.")
            success = True
    
    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main() 