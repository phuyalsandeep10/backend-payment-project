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
python manage.py makemigrations
python manage.py migrate

# Verify migrations
echo "✅ Verifying migrations..."
python manage.py showmigrations --list | grep -E "\[ \]" && echo "⚠️  Warning: Some migrations are not applied!" || echo "✅ All migrations applied successfully!"

# Setup notification templates
echo "📧 Setting up notification templates..."
python manage.py setup_notification_templates

# Create all permissions first
echo "🔐 Creating all permissions..."
python manage.py create_all_permissions

# Create deal permissions (for backward compatibility)
echo "🔐 Creating deal permissions..."
python manage.py create_deal_permissions

# Setup permissions and assign them to roles
echo "🔐 Setting up permissions and assigning to roles..."
python manage.py setup_permissions

# Verify permission setup
echo "🔍 Verifying permission setup..."
python manage.py check_permissions

echo "🎉 Build Complete!"