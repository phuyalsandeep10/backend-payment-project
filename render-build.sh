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

echo "🎉 Build Complete!"