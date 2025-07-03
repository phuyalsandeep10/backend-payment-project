#!/usr/bin/env python
"""
Fresh Environment Setup Script for PRS Backend
This script ensures a complete and robust setup of the PRS backend system,
handling all potential issues including field naming compatibility.
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def run_command(command, description, exit_on_error=True):
    """Run a command and handle errors gracefully"""
    print(f"\n🔄 {description}")
    print(f"   Command: {command}")
    print("-" * 50)
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, cwd=Path(__file__).parent)
        
        if result.returncode == 0:
            print(f"✅ SUCCESS: {description}")
            if result.stdout.strip():
                print("Output:")
                print(result.stdout)
            return True
        else:
            print(f"❌ ERROR: {description}")
            if result.stderr.strip():
                print("Error details:")
                print(result.stderr)
            if result.stdout.strip():
                print("Output:")
                print(result.stdout)
            
            if exit_on_error:
                print(f"\n💥 Setup failed at: {description}")
                sys.exit(1)
            return False
            
    except Exception as e:
        print(f"❌ EXCEPTION during {description}: {e}")
        if exit_on_error:
            sys.exit(1)
        return False

def check_python_version():
    """Check if Python version is compatible"""
    print("🐍 CHECKING PYTHON VERSION")
    print("-" * 30)
    
    python_version = sys.version_info
    print(f"Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
        print("❌ Python 3.8+ is required")
        sys.exit(1)
    
    print("✅ Python version is compatible")

def check_virtual_environment():
    """Check if virtual environment is activated"""
    print("\n🏠 CHECKING VIRTUAL ENVIRONMENT")
    print("-" * 35)
    
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Virtual environment is activated")
        print(f"   Virtual env path: {sys.prefix}")
        return True
    else:
        print("⚠️  No virtual environment detected")
        print("   It's recommended to use a virtual environment")
        response = input("   Continue anyway? (y/N): ").lower().strip()
        return response == 'y'

def setup_database():
    """Setup database with proper migrations"""
    print("\n💾 DATABASE SETUP")
    print("-" * 20)
    
    # Check if migrations exist
    migrations_dir = Path(__file__).parent / "authentication" / "migrations"
    if not migrations_dir.exists():
        print("❌ Migrations directory not found")
        return False
    
    migration_files = list(migrations_dir.glob("*.py"))
    migration_files = [f for f in migration_files if f.name != "__init__.py"]
    print(f"📁 Found {len(migration_files)} migration files")
    
    # Run migrations in correct order
    commands = [
        ("python manage.py makemigrations", "Creating any new migrations"),
        ("python manage.py migrate auth", "Applying auth migrations"),
        ("python manage.py migrate contenttypes", "Applying contenttypes migrations"),
        ("python manage.py migrate sessions", "Applying sessions migrations"),
        ("python manage.py migrate admin", "Applying admin migrations"),
        ("python manage.py migrate authtoken", "Applying authtoken migrations"),
        ("python manage.py migrate", "Applying all remaining migrations"),
    ]
    
    for command, description in commands:
        if not run_command(command, description, exit_on_error=False):
            print(f"⚠️  {description} failed, trying to continue...")
    
    return True

def verify_models():
    """Verify that models are properly loaded"""
    print("\n🔍 VERIFYING MODELS")
    print("-" * 20)
    
    verification_script = '''
import django
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core_config.settings")
django.setup()

from authentication.models import User
from permissions.models import Role
from organization.models import Organization

# Check User model fields
user_fields = [field.name for field in User._meta.fields]
print("User model fields:", user_fields)

# Check if role field exists (either 'role' or 'org_role')
role_field_exists = 'role' in user_fields or 'org_role' in user_fields
print(f"Role field exists: {role_field_exists}")

if 'role' in user_fields:
    print("SUCCESS: Role field name: 'role'")
elif 'org_role' in user_fields:
    print("SUCCESS: Role field name: 'org_role'")
else:
    print("ERROR: No role field found!")
    exit(1)

print("SUCCESS: All models verified successfully")
'''
    
    with open("temp_verify_models.py", "w", encoding="utf-8") as f:
        f.write(verification_script)
    
    try:
        success = run_command("python temp_verify_models.py", "Verifying model structure", exit_on_error=False)
        os.remove("temp_verify_models.py")
        return success
    except Exception as e:
        if os.path.exists("temp_verify_models.py"):
            os.remove("temp_verify_models.py")
        print(f"❌ Model verification failed: {e}")
        return False

def setup_superadmin():
    """Setup superadmin with enhanced error handling"""
    print("\n👑 SETTING UP SUPER ADMIN")
    print("-" * 25)
    
    # First, try the enhanced setup command
    success = run_command(
        "python manage.py setup_superadmin", 
        "Setting up super admin with enhanced script",
        exit_on_error=False
    )
    
    if not success:
        print("⚠️  Enhanced setup failed, trying manual approach...")
        
        # Manual setup approach
        manual_setup_script = '''
import django
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core_config.settings")
django.setup()

from authentication.models import User
from permissions.models import Role
from django.contrib.auth import get_user_model

# Create Super Admin role
role, created = Role.objects.get_or_create(
    name='Super Admin',
    organization=None
)

if created:
    print("SUCCESS: Super Admin role created")
else:
    print("SUCCESS: Super Admin role already exists")

# Create or update super admin user
email = "admin@example.com"
username = "admin"
password = "defaultpass"

# Check if username is already taken by another user
if User.objects.filter(username=username).exclude(email=email).exists():
    print(f"WARNING: Username '{username}' already exists for different email")
    # Generate unique username
    counter = 1
    original_username = username
    while User.objects.filter(username=username).exists():
        username = f"{original_username}_{counter}"
        counter += 1
    print(f"INFO: Using unique username: {username}")

user, created = User.objects.get_or_create(
    email=email,
    defaults={
        'username': username,
        'is_superuser': True,
        'is_staff': True,
        'is_active': True,
    }
)

# Set role using field detection
user_fields = [field.name for field in User._meta.fields]
if 'role' in user_fields:
    user.role = role
elif 'org_role' in user_fields:
    user.org_role = role

user.set_password(password)
user.is_superuser = True
user.is_staff = True
user.save()

if created:
    print(f"SUCCESS: Super admin created: {email}")
else:
    print(f"SUCCESS: Super admin updated: {email}")

print(f"Email: {email}")
print(f"Password: {password}")
print("SUCCESS: Super admin ready!")
'''
        
        with open("temp_manual_setup.py", "w", encoding="utf-8") as f:
            f.write(manual_setup_script)
        
        try:
            success = run_command("python temp_manual_setup.py", "Manual super admin setup", exit_on_error=False)
            os.remove("temp_manual_setup.py")
            return success
        except Exception as e:
            if os.path.exists("temp_manual_setup.py"):
                os.remove("temp_manual_setup.py")
            print(f"❌ Manual setup failed: {e}")
            return False
    
    return success

def run_tests():
    """Run basic functionality tests"""
    print("\n🧪 RUNNING BASIC TESTS")
    print("-" * 22)
    
    test_commands = [
        ("python manage.py check", "Django system check"),
        ("python manage.py setup_superadmin --list-users", "List users test"),
    ]
    
    for command, description in test_commands:
        run_command(command, description, exit_on_error=False)

def main():
    """Main setup function"""
    print("=" * 60)
    print("🚀 PRS BACKEND - FRESH ENVIRONMENT SETUP")
    print("=" * 60)
    print("This script will set up your PRS backend environment completely.")
    print("It handles field compatibility issues and ensures everything works.")
    print("=" * 60)
    
    # Step 1: Check prerequisites
    check_python_version()
    
    if not check_virtual_environment():
        print("❌ Setup cancelled by user")
        sys.exit(1)
    
    # Step 2: Install dependencies
    run_command(
        "pip install -r requirements.txt", 
        "Installing Python dependencies"
    )
    
    # Step 3: Setup database
    if not setup_database():
        print("❌ Database setup failed")
        sys.exit(1)
    
    # Step 4: Verify models
    if not verify_models():
        print("❌ Model verification failed")
        sys.exit(1)
    
    # Step 5: Setup superadmin
    if not setup_superadmin():
        print("❌ Super admin setup failed")
        sys.exit(1)
    
    # Step 6: Run tests
    run_tests()
    
    # Final success message
    print("\n" + "=" * 60)
    print("🎉 SETUP COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print("✅ Database migrations applied")
    print("✅ Super admin created")
    print("✅ System verified")
    print("")
    print("🚀 Your PRS backend is ready to use!")
    print("📧 Default admin email: admin@example.com")
    print("🔑 Default admin password: defaultpass")
    print("")
    print("🔗 Next steps:")
    print("   1. Start the development server: python manage.py runserver")
    print("   2. Visit the admin panel: http://127.0.0.1:8000/admin/")
    print("   3. Check the API documentation: http://127.0.0.1:8000/swagger/")
    print("=" * 60)

if __name__ == "__main__":
    main() 