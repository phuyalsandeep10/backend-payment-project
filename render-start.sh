#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to backend directory to run management commands
cd backend

# # Nuclear option: Reset database completely (set RESET_DB=true to enable)
# if [ "$RESET_DB" = "true" ]; then
#     echo "⚠️  NUCLEAR OPTION: Resetting database completely..."
#     python scripts/reset_database.py
# fi

# Clean database of orphaned data first
echo "🧹 Cleaning database of orphaned data..."
python scripts/clean_database.py

# Run database migrations
python manage.py migrate

# Fix any migration conflicts that might exist
echo "🔧 Checking for migration conflicts..."
python scripts/fix_all_migration_conflicts.py

# Fix any permission issues that might exist
echo "🔧 Checking for permission issues..."
python scripts/fix_permission_issues.py

# Initialize the application with a superuser and mock data.
# This command will run on every startup.
# It is designed to be safe to re-run, but for a production environment
# with real data, you may want to run this only once.
python manage.py initialize_app

# Fix any permission issues that might have been created during initialization
echo "🔧 Checking for permission issues after initialization..."
python scripts/fix_permission_issues.py

# Assign proper permissions to roles
echo "🔐 Assigning permissions to roles..."
python manage.py assign_role_permissions

# Generate rich, varied data for all API endpoints
python manage.py generate_rich_test_data



# Start the Gunicorn server.
# We are already in the 'backend' directory, so we point to 'core_config.wsgi'.
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT 