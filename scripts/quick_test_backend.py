#!/usr/bin/env python3
"""
Quick test script for PRS Backend with SQLite
This gets the backend running immediately for testing
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
    print("🚀 Quick setup for PRS Backend with SQLite...")
    
    # Change to backend directory
    os.chdir('backend')
    
    # Set minimal environment variables
    os.environ['SECRET_KEY'] = 'django-insecure-dev-key-change-in-production'
    os.environ['DEBUG'] = 'True'
    os.environ['SUPER_ADMIN_OTP_EMAIL'] = 'admin@example.com'
    os.environ['DEFAULT_FROM_EMAIL'] = 'noreply@example.com'
    
    print("✅ Using SQLite database (no PostgreSQL setup needed)")
    
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
            sys.exit(1)
    
    print("\n🎉 Backend setup completed successfully with SQLite!")
    print("\n📋 Your backend is now ready and compatible with the frontend!")
    print("\nNext steps:")
    print("1. Create a superuser: python manage.py createsuperuser")
    print("2. Start the server: python manage.py runserver")
    print("3. Test frontend connection: http://127.0.0.1:8000/api/")
    print("4. Admin panel: http://127.0.0.1:8000/admin/")
    print("5. API documentation: http://127.0.0.1:8000/swagger/")
    print("\n💡 To switch to PostgreSQL later, follow the instructions in BACKEND_SETUP.md")

if __name__ == "__main__":
    main() 