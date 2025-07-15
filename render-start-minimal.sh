#!/bin/bash
# exit on error
set -o errexit

cd backend

# Install dependencies (if needed)
# pip install -r requirements.txt

# Collect static files (doesn't require database)
echo "📦 Collecting static files..."
python manage.py collectstatic --no-input

# Try to run migrations, but don't fail if database is not ready
echo "🔄 Attempting to run database migrations..."
if python manage.py migrate --noinput 2>/dev/null; then
    echo "✅ Migrations completed successfully"
    
    # Try to create superuser
    echo "👤 Setting up superuser..."
    python manage.py setup_superadmin --noinput 2>/dev/null || echo "⚠️  Could not create superuser"
    
    # Try to setup permissions
    echo "🔐 Setting up permissions..."
    python manage.py setup_permissions 2>/dev/null || echo "⚠️  Could not setup permissions"
    
    # Try to initialize app
    echo "🚀 Attempting to initialize application..."
    python manage.py initialize_app 2>/dev/null || echo "⚠️  Could not initialize application"
    
    # Generate test data only in development
    if [ "$DEBUG" = "True" ]; then
        echo "🧪 Generating test data..."
        python manage.py generate_rich_test_data 2>/dev/null || echo "⚠️  Could not generate test data"
    fi
else
    echo "⚠️  Database not ready, skipping migrations and setup"
    echo "🔄 You can run the following commands manually once the database is ready:"
    echo "   python manage.py migrate"
    echo "   python manage.py setup_superadmin"
    echo "   python manage.py setup_permissions"
    echo "   python manage.py initialize_app"
fi

# Start the application
echo "🚀 Starting the application..."
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT 