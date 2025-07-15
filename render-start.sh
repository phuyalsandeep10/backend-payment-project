#!/bin/bash
# exit on error
set -o errexit

# Install dependencies

cd backend
# Collect static files
# python manage.py collectstatic --no-input

# Function to check database connectivity
check_database() {
    echo "🔍 Checking database connectivity..."
    python manage.py check --database default 2>/dev/null || {
        echo "⚠️  Database not ready, waiting..."
        return 1
    }
    echo "✅ Database is ready!"
    return 0
}

# Wait for database to be ready (max 5 minutes)
echo "🔄 Waiting for database to be ready..."
for i in {1..30}; do
    if check_database; then
        break
    fi
    echo "⏳ Attempt $i/30 - Waiting 10 seconds..."
    sleep 10
done

# Final database check
if ! check_database; then
    echo "❌ Database is not accessible after 5 minutes. Please check your database configuration."
    echo "🔧 Make sure:"
    echo "   - Database service is running"
    echo "   - Environment variables are correct"
    echo "   - Database and web service are properly linked"
    exit 1
fi
python manage.py initialize_app
# Run database migrations
echo "🔄 Running database migrations..."
python manage.py migrate

# # Create superuser if it doesn't exist
# echo "👤 Setting up superuser..."
# python manage.py setup_superadmin --noinput

# Setup permissions
# echo "🔐 Setting up permissions..."
# python manage.py setup_permissions

# Generate test data only in development
if [ "$DEBUG" = "True" ]; then
    echo "🧪 Generating test data..."
    python manage.py generate_rich_test_data
fi

# Start the application
echo "🚀 Starting the application..."
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT