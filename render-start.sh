#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to backend directory to run management commands
cd backend

# Run database migrations
python manage.py migrate

# Fix any migration conflicts that might exist
echo "🔧 Checking for migration conflicts..."
python scripts/fix_all_migration_conflicts.py

# Initialize the application with a superuser and mock data.
# This command will run on every startup.
# It is designed to be safe to re-run, but for a production environment
# with real data, you may want to run this only once.
python manage.py initialize_app

# Create custom permissions and assign them to roles

# Generate rich, varied data for all API endpoints
python manage.py generate_rich_test_data

# Start the Gunicorn server.
# We are already in the 'backend' directory, so we point to 'core_config.wsgi'.
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT 