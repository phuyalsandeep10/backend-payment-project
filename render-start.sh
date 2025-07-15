#!/bin/bash
# Safe startup script for Render deployment
# Handles database connectivity issues gracefully

set -e  # Exit on any error

echo "🚀 Starting PRS Backend on Render..."
echo "=================================="

cd backend
python debug_database.py


python manage.py initialize_app --flush
python manage.py generate_rich_test_data
# Collect static files (doesn't require database)

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