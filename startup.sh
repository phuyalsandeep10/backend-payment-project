#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to the backend directory where manage.py is located
cd backend

echo "🚀 Starting application setup..."

# Run migrations
echo "📦 Running database migrations..."
python manage.py migrate

# Create default roles and permissions first
echo "🎭 Creating default roles and permissions..."
python manage.py create_default_roles

# Run initialization to create TechCorp organization and mock data
echo "🏢 Creating TechCorp organization and mock data..."
python manage.py initialize_app

echo "✅ Application setup completed successfully!"
echo "🔗 Available endpoints:"
echo "   - /auth/login/direct/ (Direct login without OTP)"
echo "   - /auth/login/ (Login with OTP)"
echo "   - /auth/register/ (User registration)"

# Start Gunicorn from the backend directory
echo "🚀 Starting Gunicorn server..."
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT