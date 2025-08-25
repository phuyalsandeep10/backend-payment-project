#!/usr/bin/env python3
"""
Setup script for PRS Backend
This script helps set up the backend for development
"""

import os
import subprocess
import sys

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed")
        print(f"Error: {e.stderr}")
        return False

def main():
    print("🚀 Setting up PRS Backend with PostgreSQL...")
    
    # Change to backend directory
    os.chdir('backend')
    
    # Set environment variables for PostgreSQL (using system user)
    os.environ['SECRET_KEY'] = 'django-insecure-dev-key-change-in-production'
    os.environ['DEBUG'] = 'True'
    os.environ['DB_NAME'] = 'postgres'
    os.environ['DB_USER'] = 'shishirkafle'  # Use system user
    os.environ['DB_PASSWORD'] = ''          # No password for system user
    os.environ['DB_HOST'] = 'localhost'
    os.environ['DB_PORT'] = '5432'
    os.environ['SUPER_ADMIN_OTP_EMAIL'] = 'admin@example.com'
    os.environ['DEFAULT_FROM_EMAIL'] = 'noreply@example.com'
    
    print("✅ Environment variables set for PostgreSQL")
    print("📋 Database Config:")
    print("   - Database: postgres")
    print("   - User: shishirkafle (system user)") 
    print("   - Host: localhost:5432")
    print("   - Password: (none - using system authentication)")
    
    # Commands to run
    commands = [
        ("python manage.py makemigrations", "Creating database migrations"),
        ("python manage.py migrate", "Applying database migrations"),
        ("python manage.py collectstatic --noinput", "Collecting static files"),
    ]
    
    # Run each command
    for command, description in commands:
        if not run_command(command, description):
            print(f"\n❌ Setup failed at: {description}")
            print("\n💡 Troubleshooting:")
            print("1. Make sure PostgreSQL is running:")
            print("   brew services start postgresql@17")
            print("2. Check if you can connect manually:")
            print("   psql -d postgres")
            print("3. Create database if it doesn't exist:")
            print("   createdb postgres")
            sys.exit(1)
    
    print("\n🎉 Backend setup completed successfully!")
    print("\nNext steps:")
    print("1. Create a superuser: python manage.py createsuperuser")
    print("2. Start the server: python manage.py runserver")
    print("3. API will be available at: http://127.0.0.1:8000/api/")
    print("4. Admin panel: http://127.0.0.1:8000/admin/")
    print("5. API documentation: http://127.0.0.1:8000/swagger/")

if __name__ == "__main__":
    main() 