#!/usr/bin/env python
"""
Comprehensive database debugging script for Render deployment.
This script provides detailed diagnostics for database connection issues.
"""
import os
import sys
import socket
import subprocess
import django
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

def check_environment_variables():
    """Check all database-related environment variables."""
    print("🔍 Environment Variables Check")
    print("=" * 50)
    
    db_vars = {
        'DATABASE_URL': 'Database URL (recommended)',
        'DB_NAME': 'Database name (legacy)',
        'DB_HOST': 'Database host (legacy)',
        'DB_USER': 'Database user (legacy)',
        'DB_PASSWORD': 'Database password (legacy)',
        'DB_PORT': 'Database port (legacy)',
        'DB_ENGINE': 'Database engine (legacy)',
    }
    
    all_set = True
    for var, description in db_vars.items():
        value = os.getenv(var)
        if value:
            # Mask sensitive values
            if 'PASSWORD' in var or 'SECRET' in var:
                display_value = '*' * min(len(value), 8)
            else:
                display_value = value
            print(f"✅ {var}: {display_value}")
        else:
            print(f"❌ {var}: Not set")
            all_set = False
    
    return all_set

def check_network_connectivity(host, port):
    """Check if we can reach the database host."""
    print(f"\n🌐 Network Connectivity Check")
    print("=" * 50)
    
    try:
        # Try to resolve the hostname
        print(f"🔍 Resolving hostname: {host}")
        ip_address = socket.gethostbyname(host)
        print(f"✅ Hostname resolved to: {ip_address}")
        
        # Try to connect to the port
        print(f"🔌 Testing connection to {host}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        if result == 0:
            print(f"✅ Connection to {host}:{port} successful")
            return True
        else:
            print(f"❌ Connection to {host}:{port} failed (error code: {result})")
            return False
            
    except socket.gaierror as e:
        print(f"❌ Could not resolve hostname '{host}': {e}")
        return False
    except Exception as e:
        print(f"❌ Network error: {e}")
        return False

def check_django_settings():
    """Check Django database settings."""
    print(f"\n⚙️  Django Settings Check")
    print("=" * 50)
    
    try:
        django.setup()
        from django.conf import settings
        
        db_settings = settings.DATABASES['default']
        
        print(f"Database Engine: {db_settings['ENGINE']}")
        print(f"Database Name: {db_settings['NAME']}")
        print(f"Database Host: {db_settings['HOST']}")
        print(f"Database Port: {db_settings['PORT']}")
        print(f"Database User: {db_settings['USER']}")
        print(f"Password Set: {'Yes' if db_settings['PASSWORD'] else 'No'}")
        
        return db_settings
        
    except Exception as e:
        print(f"❌ Error loading Django settings: {e}")
        return None

def test_database_connection():
    """Test actual database connection."""
    print(f"\n🔌 Database Connection Test")
    print("=" * 50)
    
    try:
        from django.db import connection
        
        # Test connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT version();")
            version = cursor.fetchone()
            print(f"✅ Database connection successful!")
            print(f"   PostgreSQL version: {version[0]}")
            
            # Check current database
            cursor.execute("SELECT current_database();")
            current_db = cursor.fetchone()
            print(f"   Current database: {current_db[0]}")
            
            # Test simple query
            cursor.execute("SELECT 1;")
            result = cursor.fetchone()
            print(f"   Simple query test: {result[0]}")
            
            return True
            
    except Exception as e:
        print(f"❌ Database connection failed: {str(e)}")
        print(f"   Error type: {type(e).__name__}")
        
        # Provide specific troubleshooting advice
        error_msg = str(e).lower()
        if "name or service not known" in error_msg:
            print("\n🔧 DNS Resolution Error:")
            print("   - Check if DB_HOST is correct")
            print("   - Verify database service is running")
            print("   - Ensure services are properly linked on Render")
        elif "connection refused" in error_msg:
            print("\n🔧 Connection Refused Error:")
            print("   - Database service may not be running")
            print("   - Check if port number is correct")
            print("   - Verify firewall settings")
        elif "authentication failed" in error_msg:
            print("\n🔧 Authentication Error:")
            print("   - Check DB_USER and DB_PASSWORD")
            print("   - Verify user exists in database")
            print("   - Check user permissions")
        elif "database does not exist" in error_msg:
            print("\n🔧 Database Not Found Error:")
            print("   - Check if DB_NAME is correct")
            print("   - Database may need to be created")
            print("   - Verify database exists on the server")
        
        return False

def check_render_environment():
    """Check if we're running on Render and provide specific advice."""
    print(f"\n🏗️  Render Environment Check")
    print("=" * 50)
    
    # Check for Render-specific environment variables
    render_vars = ['RENDER', 'RENDER_EXTERNAL_HOSTNAME', 'RENDER_SERVICE_ID']
    render_detected = any(os.getenv(var) for var in render_vars)
    
    if render_detected:
        print("✅ Running on Render")
        
        # Check for common Render database variables
        if os.getenv('DATABASE_URL'):
            print("✅ DATABASE_URL found (Render PostgreSQL)")
            print("   - This is the recommended approach")
        else:
            print("⚠️  DATABASE_URL not found")
            print("   - Make sure you've created a PostgreSQL service")
            print("   - Link it to your web service")
            print("   - Render should automatically provide DATABASE_URL")
        
        # Check if we're in a web service
        if os.getenv('RENDER_SERVICE_ID'):
            print(f"✅ Web service detected: {os.getenv('RENDER_SERVICE_ID')}")
        
        return True
    else:
        print("⚠️  Not running on Render (or Render variables not detected)")
        return False

def provide_troubleshooting_advice():
    """Provide comprehensive troubleshooting advice."""
    print(f"\n🔧 Troubleshooting Guide")
    print("=" * 50)
    
    print("1. Check Render Dashboard:")
    print("   - Go to your Render dashboard")
    print("   - Verify PostgreSQL service is running")
    print("   - Check if web service is linked to database")
    print("   - Review environment variables")
    
    print("\n2. Environment Variables:")
    print("   - DATABASE_URL: Your full database URL (recommended)")
    print("     Format: postgresql://user:password@host:port/database")
    print("   - Or individual variables (legacy):")
    print("     - DB_NAME: Your database name")
    print("     - DB_HOST: Your database host (from Render)")
    print("     - DB_USER: Your database username")
    print("     - DB_PASSWORD: Your database password")
    print("     - DB_PORT: Usually 5432")
    print("     - DB_ENGINE: django.db.backends.postgresql")
    
    print("\n3. Common Solutions:")
    print("   - Wait 2-5 minutes for database to initialize")
    print("   - Restart your web service")
    print("   - Check database service logs")
    print("   - Verify service linking in Render dashboard")
    
    print("\n4. Alternative: Use SQLite")
    print("   - Remove all DB_* environment variables")
    print("   - Django will automatically use SQLite")
    print("   - Good for testing, not recommended for production")

def main():
    """Main diagnostic function."""
    print("🚀 PRS Backend Database Diagnostics")
    print("=" * 60)
    
    # Check environment variables
    env_ok = check_environment_variables()
    
    # Check if we're on Render
    render_ok = check_render_environment()
    
    # Check Django settings
    db_settings = check_django_settings()
    
    # Test network connectivity if we have host info
    network_ok = False
    if db_settings and db_settings.get('HOST') and db_settings.get('PORT'):
        network_ok = check_network_connectivity(
            db_settings['HOST'], 
            db_settings['PORT']
        )
    
    # Test database connection
    db_ok = test_database_connection()
    
    # Provide summary
    print(f"\n📊 Diagnostic Summary")
    print("=" * 50)
    print(f"Environment Variables: {'✅ OK' if env_ok else '❌ ISSUES'}")
    print(f"Render Environment: {'✅ OK' if render_ok else '⚠️  NOT DETECTED'}")
    print(f"Network Connectivity: {'✅ OK' if network_ok else '❌ FAILED'}")
    print(f"Database Connection: {'✅ OK' if db_ok else '❌ FAILED'}")
    
    if db_ok:
        print("\n🎉 All checks passed! Database is working correctly.")
    else:
        print("\n⚠️  Some checks failed. Review the details above.")
        provide_troubleshooting_advice()
        
        # Exit with error code for automation
        sys.exit(1)

if __name__ == '__main__':
    main() 