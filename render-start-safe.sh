#!/bin/bash
# Safe startup script for Render deployment
# Handles database connectivity issues gracefully

set -e  # Exit on any error

echo "🚀 Starting PRS Backend on Render..."
echo "=================================="

cd backend

# Function to check if database environment variables are set
check_db_env_vars() {
    echo "🔍 Checking database environment variables..."
    
    # Check for DATABASE_URL first (recommended approach)
    if [ -n "$DATABASE_URL" ]; then
        echo "✅ DATABASE_URL is set (recommended)"
        return 0
    fi
    
    # Fallback to individual variables
    local required_vars=("DB_NAME" "DB_HOST" "DB_USER" "DB_PASSWORD")
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -eq 0 ]; then
        echo "✅ All individual database environment variables are set"
        return 0
    else
        echo "⚠️  Missing database environment variables: ${missing_vars[*]}"
        echo "🔧 Will use SQLite fallback"
        return 1
    fi
}

# Function to test database connectivity
test_db_connection() {
    echo "🔌 Testing database connection..."
    
    # Try to run a simple Django command that requires database
    if python manage.py check --database default >/dev/null 2>&1; then
        echo "✅ Database connection successful"
        return 0
    else
        echo "❌ Database connection failed"
        return 1
    fi
}

# Function to wait for database with timeout
wait_for_database() {
    echo "⏳ Waiting for database to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        echo "   Attempt $attempt/$max_attempts..."
        
        if test_db_connection; then
            echo "✅ Database is ready!"
            return 0
        fi
        
        if [ $attempt -lt $max_attempts ]; then
            echo "   Waiting 10 seconds before next attempt..."
            sleep 10
        fi
        
        ((attempt++))
    done
    
    echo "❌ Database not ready after $max_attempts attempts"
    return 1
}

# Function to setup SQLite fallback
setup_sqlite_fallback() {
    echo "🔄 Setting up SQLite fallback..."
    
    # Temporarily unset database environment variables
    export DATABASE_URL=""
    export DB_NAME=""
    export DB_HOST=""
    export DB_USER=""
    export DB_PASSWORD=""
    export DB_PORT=""
    export DB_ENGINE=""
    
    echo "✅ SQLite fallback configured"
}

# Function to run database operations
run_db_operations() {
    echo "🔄 Running database operations..."
    
    # Run migrations
    echo "   Running migrations..."
    if python manage.py migrate --noinput; then
        echo "   ✅ Migrations completed"
    else
        echo "   ❌ Migrations failed"
        return 1
    fi
    
    # Setup superuser
    echo "   Setting up superuser..."
    if python manage.py setup_superadmin --noinput; then
        echo "   ✅ Superuser setup completed"
    else
        echo "   ⚠️  Superuser setup failed (may already exist)"
    fi
    
    # Setup permissions
    echo "   Setting up permissions..."
    if python manage.py setup_permissions; then
        echo "   ✅ Permissions setup completed"
    else
        echo "   ⚠️  Permissions setup failed (may already exist)"
    fi
    
    # Initialize app
    echo "   Initializing application..."
    if python manage.py initialize_app --flush; then
        echo "   ✅ Application initialization completed"
    else
        echo "   ⚠️  Application initialization failed (may already be initialized)"
    fi
    
    # Generate test data only in development
    if [ "$DEBUG" = "True" ]; then
        echo "   Generating test data..."
        if python manage.py generate_rich_test_data; then
            echo "   ✅ Test data generated"
        else
            echo "   ⚠️  Test data generation failed"
        fi
    fi
    
    return 0
}

# Function to collect static files
collect_static() {
    echo "📦 Collecting static files..."
    if python manage.py collectstatic --noinput; then
        echo "✅ Static files collected"
    else
        echo "⚠️  Static file collection failed"
    fi
}

# Main execution flow
echo "🔧 Environment check..."

# Check if we're in production or development
if [ "$DEBUG" = "True" ]; then
    echo "   Mode: Development"
else
    echo "   Mode: Production"
fi

# Check database environment variables
if check_db_env_vars; then
    echo "🔍 Database environment variables are set, attempting PostgreSQL connection..."
    
    # Wait for database to be ready
    if wait_for_database; then
        echo "✅ PostgreSQL database is ready"
        db_type="postgresql"
    else
        echo "⚠️  PostgreSQL database not ready, falling back to SQLite"
        setup_sqlite_fallback
        db_type="sqlite"
    fi
else
    echo "⚠️  Database environment variables not set, using SQLite"
    setup_sqlite_fallback
    db_type="sqlite"
fi

# Collect static files (doesn't require database)
collect_static

# Run database operations
if run_db_operations; then
    echo "✅ Database operations completed successfully"
else
    echo "❌ Database operations failed"
    echo "🔧 Continuing anyway to allow manual setup..."
fi

# Display final status
echo ""
echo "=================================="
echo "🎉 Application startup completed!"
echo "   Database type: $db_type"
echo "   Debug mode: $DEBUG"
echo "   Port: $PORT"
echo "=================================="

# Start the application
echo "🚀 Starting Gunicorn server..."
exec gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT --workers 2 --timeout 120 