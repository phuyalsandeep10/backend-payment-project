#!/usr/bin/env bash
# exit on error
set -o errexit

echo "🚀 Starting Render deployment..."

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Fix migration conflicts before running migrations
echo "🔧 Fixing migration conflicts..."
# python manage.py flush

# Handle problematic migrations with fake
# echo "🎭 Handling problematic migrations..."
# python manage.py migrate authentication 0007_auto_20250715_2117 --fake || echo "Migration already applied or doesn't exist"
# python manage.py migrate authentication 0008_user_login_count --fake || echo "Migration already applied or doesn't exist"

# Run all migrations
echo "🔄 Running all migrations..."
python manage.py migrate

# Collect static files
echo "📁 Collecting static files..."
python manage.py collectstatic --no-input

echo "✅ Deployment completed successfully!"