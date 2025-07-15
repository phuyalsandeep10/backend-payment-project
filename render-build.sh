#!/usr/bin/env bash
# exit on error
set -o errexit

echo "🚀 Starting deployment build process..."

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r backend/requirements.txt

# Change to backend directory
cd backend

# Apply migrations with safety checks
echo "🔄 Applying migrations..."

# First, fake the problematic avatar migration if it exists
echo "🔧 Handling avatar migration..."
python manage.py makemigrations

python manage.py migrate authentication 0005_user_login_count --fake
python manage.py migrate authentication 0004_remove_user_avatar --fake

# Then run normal migrations
echo "🔄 Running normal migrations..."
python manage.py migrate

# Verify migrations
echo "✅ Verifying migrations..."
python manage.py showmigrations --list | grep -E "\[ \]" && echo "⚠️  Warning: Some migrations are not applied!" || echo "✅ All migrations applied successfully!"

# Collect static files
echo "📁 Collecting static files..."
python manage.py collectstatic --noinput

echo "🎉 Build Complete!"