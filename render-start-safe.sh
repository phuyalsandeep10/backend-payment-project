#!/usr/bin/env bash
# exit on error
set -o errexit

echo "🚀 Starting safe deployment process..."

# Change to backend directory
cd backend

# Step 1: Handle problematic migrations safely
echo "🔧 Handling problematic migrations..."
python manage.py migrate authentication 0004_remove_user_avatar --fake 2>/dev/null || echo "Avatar migration already handled"

# Step 2: Run all other migrations
echo "🔄 Running database migrations..."
python manage.py migrate

# Step 3: Initialize app with data
echo "🔄 Initializing application..."
python manage.py initialize_app --flush

# Step 4: Setup permissions
echo "🔐 Setting up permissions..."
python manage.py create_all_permissions
python manage.py assign_role_permissions

# Step 5: Generate test data
echo "📊 Generating test data..."
python manage.py generate_rich_test_data --deals 10 --clients 3 --projects 2

echo "🎉 Safe deployment complete!"

# Start the Gunicorn server
echo "🚀 Starting Gunicorn server..."
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT 