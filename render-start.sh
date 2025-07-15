#!/bin/bash
# Safe startup script for Render deployment
# Handles database connectivity issues gracefully

set -e  # Exit on any error

echo "🚀 Starting PRS Backend on Render..."
echo "=================================="

cd backend
python debug_database.py

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


python manage.py initialize_app --flush
python manage.py generate_rich_test_data
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