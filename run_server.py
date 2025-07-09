#!/usr/bin/env python3
"""
Simple script to run the Django development server
Sets required environment variables and starts the server
"""

import os
import subprocess
import sys

def main():
    print("🚀 Starting PRS Backend Server...")
    
    # Set environment variables
    os.environ['SECRET_KEY'] = 'django-insecure-dev-key-change-in-production-12345'
    os.environ['DEBUG'] = 'True'
    os.environ['SUPER_ADMIN_OTP_EMAIL'] = 'admin@example.com'
    os.environ['DEFAULT_FROM_EMAIL'] = 'noreply@example.com'
    
    # Change to backend directory
    os.chdir('backend')
    
    print("✅ Environment variables set")
    print("🌐 Starting server at http://127.0.0.1:8000/")
    print("📋 API endpoints available at http://127.0.0.1:8000/api/")
    print("🔧 Admin panel at http://127.0.0.1:8000/admin/")
    print("\n🛑 Press Ctrl+C to stop the server\n")
    
    # Run the server
    try:
        subprocess.run(['python', 'manage.py', 'runserver'], check=True)
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 