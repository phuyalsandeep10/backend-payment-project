#!/usr/bin/env bash
# exit on error
set -o errexit

echo "🚀 Starting deployment build process..."

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r backend/requirements.txt

# Change to backend directory
cd backend



echo "📁 Collecting static files..."
python manage.py collectstatic --noinput
python manage.py makemigrations

echo "🎉 Fixing deployment migrations..."
python scripts/fix_deployment_migrations.py
python manage.py makemigrations
python manage.py migrate authentication 0007_auto_20250715_2117 --fake
python manage.py migrate

echo "🎉 Build Complete!"