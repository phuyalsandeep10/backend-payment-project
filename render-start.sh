#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to backend directory to run management commands
cd backend

# In a production environment, data initialization and mock data generation
# must not be run. These steps are for development/staging only.
# Database migrations are handled by the build script (render-build.sh).
# The start command should only be responsible for running the application server.

# Start the Gunicorn server.
# We are already in the 'backend' directory, so we point to 'core_config.wsgi'.
echo "🚀 Starting Gunicorn server for production..."
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT 