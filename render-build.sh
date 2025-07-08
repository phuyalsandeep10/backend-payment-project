#!/usr/bin/env bash
# exit on error
set -o errexit
set -o pipefail
 
echo "🚀 Starting deployment build process..."

# Install dependencies
echo "--> Installing dependencies..."
pip install -r backend/requirements.txt

# Change to backend directory
cd backend

# This build script is for a non-production environment where the database is reset on each deploy.
# For production, the flush and initialize_app commands must be removed.
echo "--> Flushing the database to ensure a clean state..."
python manage.py flush --no-input

# Apply migrations with safety checks
echo "--> Applying database migrations..."
python manage.py makemigrations
python manage.py migrate

# Verify migrations
echo "--> Verifying migration status..."
if python manage.py showmigrations --list | grep -E "\[ \]"; then
    echo "⚠️  Warning: Some migrations are not applied! Check the migration plan."
else
    echo "✅ All migrations applied successfully!"
fi

# Setup notification templates
echo "--> Setting up notification templates..."
python manage.py setup_notification_templates

echo "🎉 Build Complete!"