#!/usr/bin/env python
"""
Render Environment Setup Helper
This script helps you set up the correct environment variables for Render deployment.
"""
import os
import sys

def print_render_setup_instructions():
    """Print step-by-step instructions for setting up Render."""
    print("🚀 Render Deployment Setup Guide")
    print("=" * 60)
    
    print("\n1. Create PostgreSQL Database on Render:")
    print("   - Go to Render Dashboard")
    print("   - Click 'New +' → 'PostgreSQL'")
    print("   - Choose a name (e.g., 'prs-database')")
    print("   - Select your plan (Free tier works for testing)")
    print("   - Click 'Create Database'")
    print("   - Wait 2-5 minutes for initialization")
    
    print("\n2. Create Web Service on Render:")
    print("   - Go to Render Dashboard")
    print("   - Click 'New +' → 'Web Service'")
    print("   - Connect your GitHub repository")
    print("   - Set the following configuration:")
    print("     * Name: prs-backend")
    print("     * Environment: Python 3")
    print("     * Build Command: pip install -r requirements.txt")
    print("     * Start Command: ./render-start-safe.sh")
    print("     * Plan: Free")
    
    print("\n3. Link Database to Web Service:")
    print("   - In your web service settings")
    print("   - Go to 'Environment' tab")
    print("   - Click 'Link Database'")
    print("   - Select your PostgreSQL database")
    print("   - Render will automatically add environment variables")
    
    print("\n4. Required Environment Variables:")
    print("   The following variables should be automatically set by Render:")
    print("   - DB_NAME (from linked database)")
    print("   - DB_HOST (from linked database)")
    print("   - DB_USER (from linked database)")
    print("   - DB_PASSWORD (from linked database)")
    print("   - DB_PORT (usually 5432)")
    print("   - DB_ENGINE (django.db.backends.postgresql)")
    
    print("\n5. Additional Environment Variables to Set:")
    print("   - SECRET_KEY (generate a secure key)")
    print("   - DEBUG (set to False for production)")
    print("   - ALLOWED_HOSTS (your domain)")
    print("   - CORS_ALLOWED_ORIGINS (your frontend domain)")
    
    print("\n6. Generate SECRET_KEY:")
    print("   Run this command to generate a secure secret key:")
    print("   python -c \"from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())\"")
    
    print("\n7. Deploy and Monitor:")
    print("   - Click 'Deploy' in your web service")
    print("   - Monitor the logs for any errors")
    print("   - Use the debug script if needed: python debug_database.py")

def check_current_environment():
    """Check current environment variables."""
    print("\n🔍 Current Environment Check")
    print("=" * 40)
    
    db_vars = ['DB_NAME', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_PORT', 'DB_ENGINE']
    render_vars = ['RENDER', 'RENDER_EXTERNAL_HOSTNAME', 'RENDER_SERVICE_ID']
    
    print("Database Variables:")
    for var in db_vars:
        value = os.getenv(var)
        if value:
            if 'PASSWORD' in var:
                print(f"  ✅ {var}: {'*' * 8}")
            else:
                print(f"  ✅ {var}: {value}")
        else:
            print(f"  ❌ {var}: Not set")
    
    print("\nRender Variables:")
    for var in render_vars:
        value = os.getenv(var)
        if value:
            print(f"  ✅ {var}: {value}")
        else:
            print(f"  ❌ {var}: Not set")

def generate_secret_key():
    """Generate a secure Django secret key."""
    try:
        import django
        from django.core.management.utils import get_random_secret_key
        secret_key = get_random_secret_key()
        print(f"\n🔑 Generated SECRET_KEY:")
        print(f"SECRET_KEY={secret_key}")
        return secret_key
    except ImportError:
        print("\n⚠️  Django not available, using alternative method...")
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*(-_=+)"
        secret_key = ''.join(secrets.choice(alphabet) for i in range(50))
        print(f"\n🔑 Generated SECRET_KEY:")
        print(f"SECRET_KEY={secret_key}")
        return secret_key

def main():
    """Main function."""
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "check":
            check_current_environment()
        elif command == "secret":
            generate_secret_key()
        elif command == "help":
            print_render_setup_instructions()
        else:
            print(f"Unknown command: {command}")
            print("Available commands: check, secret, help")
    else:
        print_render_setup_instructions()
        print("\n" + "=" * 60)
        print("Quick Commands:")
        print("  python setup_render_env.py check  - Check current environment")
        print("  python setup_render_env.py secret - Generate SECRET_KEY")
        print("  python setup_render_env.py help   - Show setup instructions")

if __name__ == '__main__':
    main() 