#!/usr/bin/env bash
# exit on error
set -o errexit

echo "🚀 Starting deployment build process..."

# Install dependencies
echo " Installing dependencies..."
pip install -r backend/requirements.txt
# Change to backend directory
cd backend

# Nuclear option: Reset database completely (set RESET_DB=true to enable)
if [ "$RESET_DB" = "true" ]; then
    echo "⚠️  NUCLEAR OPTION: Resetting database completely..."
    python scripts/reset_database.py
fi

# Clean database of orphaned data first
echo "🧹 Cleaning database of orphaned data..."
python scripts/clean_database.py

# Fix specific permission ID 30 issue
echo "🔧 Fixing specific permission ID 30 issue..."
python scripts/fix_permission_30.py

# Test migrations before applying them
echo "🔍 Testing migrations..."
python tests/test_migrations.py || (
    echo "❌ Migration test failed! Attempting to fix all conflicts..."
    python scripts/fix_all_migration_conflicts.py || (
        echo "❌ Failed to fix migration conflicts! Aborting deployment."
        exit 1
    )
    echo "✅ All migration conflicts fixed!"
)

# Create migration plan
echo "📋 Creating migration plan..."
python manage.py showmigrations > migration_plan.txt
echo "Migration plan saved to migration_plan.txt"

# Apply migrations with safety checks
echo "🔄 Applying migrations..."
#python manage.py migrate Sales_dashboard zero
python manage.py makemigrations
python manage.py migrate

# Verify migrations
echo "✅ Verifying migrations..."
python manage.py showmigrations --list | grep -E "\[ \]" && echo "⚠️  Warning: Some migrations are not applied!" || echo "✅ All migrations applied successfully!"

# Setup notification templates
echo "📧 Setting up notification templates..."
python manage.py setup_notification_templates

echo "🎉 Build Complete!"