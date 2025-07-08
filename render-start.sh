#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to backend directory to run management commands
cd backend

# In a production environment, data initialization and mock data generation
# must not be run. These steps are for development/staging only.
# Database migrations are handled by the build script (render-build.sh).
# The start command should only be responsible for running the application server.
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
echo "🚀 Starting Gunicorn server for production..."
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT 