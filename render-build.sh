#!/usr/bin/env bash
# exit on error
set -o errexit

echo "🚀 Starting deployment build process..."

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r backend/requirements.txt

# Change to backend directory
cd backend

# # Nuclear option: Reset database completely (set RESET_DB=true to enable)
# if [ "$RESET_DB" = "true" ]; then
#     echo "⚠️  NUCLEAR OPTION: Resetting database completely..."
#     echo "This will destroy all data and start fresh!"
#     python manage.py nuclear_reset_db --force
#     echo "✅ Database reset completed!"
# fi

# # Clean database of orphaned data first
# echo "🧹 Cleaning database of orphaned data..."
# python manage.py cleanup_permissions

# # Test migrations before applying them
# echo "🔍 Testing migrations..."
# python manage.py showmigrations --list > migration_status.txt
# echo "Migration status saved to migration_status.txt"

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

# # Setup permissions and assign them to roles
# echo "🔐 Setting up permissions and assigning to roles..."
# python manage.py setup_permissions

echo "🎉 Build Complete!"